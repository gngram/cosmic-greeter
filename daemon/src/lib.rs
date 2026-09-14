use cosmic_comp_config::output::randr;
use cosmic_config::CosmicConfigEntry;
use kdl::KdlDocument;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub use cosmic_applets_config::time::TimeAppletConfig;
pub use cosmic_bg_config::state::State as BgState;
pub use cosmic_bg_config::{Color, Source as BgSource};
pub use cosmic_comp_config::{CosmicCompConfig, XkbConfig, ZoomConfig};
pub use cosmic_theme::{Theme, ThemeBuilder};

pub struct UserFilter {
    uid_min: u32,
    uid_max: u32,
}

impl Default for UserFilter {
    fn default() -> Self {
        let login_defs_data = fs::read_to_string("/etc/login.defs").unwrap_or_default();
        let login_defs = whitespace_conf::parse(&login_defs_data);
        Self {
            uid_min: login_defs
                .get("UID_MIN")
                .and_then(|x| x.parse::<u32>().ok())
                .unwrap_or(1000),
            uid_max: login_defs
                .get("UID_MAX")
                .and_then(|x| x.parse::<u32>().ok())
                .unwrap_or(65000),
        }
    }
}

impl UserFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uid_min(&self) -> u32 {
        self.uid_min
    }

    pub fn uid_max(&self) -> u32 {
        self.uid_max
    }

    fn has_valid_shell(shell: &str) -> bool {
        match Path::new(shell).file_name().and_then(|x| x.to_str()) {
            // Skip shell ending in false
            Some("false") => false,
            // Skip shell ending in nologin
            Some("nologin") => false,
            _ => true,
        }
    }

    /// Filter for local enumeration (/etc/passwd) using UID_MIN..=UID_MAX bounds
    pub fn filter_local(&self, user: &pwd::Passwd) -> bool {
        if user.uid < self.uid_min || user.uid > self.uid_max || user.uid == 65534 || user.uid == u32::MAX {
            return false;
        }
        Self::has_valid_shell(&user.shell)
    }

    /// Filter for cached / directory service users (allows 32-bit mapped enterprise UIDs)
    pub fn filter_cached(&self, user: &pwd::Passwd) -> bool {
        if user.uid < self.uid_min || user.uid == 65534 || user.uid == u32::MAX {
            return false;
        }
        Self::has_valid_shell(&user.shell)
    }

    pub fn filter(&self, user: &pwd::Passwd) -> bool {
        self.filter_cached(user)
    }
}

#[zbus::proxy(
    default_service = "org.freedesktop.Accounts",
    default_path = "/org/freedesktop/Accounts",
    interface = "org.freedesktop.Accounts"
)]
pub trait Accounts {
    fn list_cached_users(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;
    fn find_user_by_name(&self, name: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.Accounts",
    interface = "org.freedesktop.Accounts.User"
)]
pub trait AccountsUser {
    #[zbus(property)]
    fn user_name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn real_name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn uid(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn icon_file(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn shell(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn system_account(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct UserData {
    pub uid: u32,
    pub name: String,
    pub full_name: String,
    pub icon_opt: Option<Vec<u8>>,
    pub theme_opt: Option<Theme>,
    pub theme_builder_opt: Option<ThemeBuilder>,
    pub bg_state: BgState,
    pub bg_path_data: BTreeMap<PathBuf, Vec<u8>>,
    pub xkb_config_opt: Option<XkbConfig>,
    pub time_applet_config: TimeAppletConfig,
    pub accessibility_zoom: ZoomConfig,
    pub kdl_output_lists: Vec<String>,
}

impl UserData {
    pub fn load_wallpapers_as_user(&mut self) {
        //TODO: reload changed background files?
        self.bg_path_data.retain(|path, _| {
            self.bg_state
                .wallpapers
                .iter()
                .any(|(_, source)| match source {
                    BgSource::Path(source_path) => source_path == path,
                    _ => false,
                })
        });
        for (_, source) in self.bg_state.wallpapers.iter() {
            //TODO: do not reread duplicate paths, cache data by path?
            if let BgSource::Path(path) = source
                && !self.bg_path_data.contains_key(path)
            {
                match fs::read(path) {
                    Ok(bytes) => {
                        self.bg_path_data.insert(path.clone(), bytes);
                    }
                    Err(err) => {
                        tracing::error!("failed to read wallpaper {:?}: {:?}", path, err);
                    }
                }
            }
        }
    }

    pub fn load_config_as_user(&mut self) {
        self.load_config_as_user_with_icon(None);
    }

    pub fn load_config_as_user_with_icon(&mut self, icon_file_opt: Option<&str>) {
        self.icon_opt = None;
        self.theme_opt = None;
        self.theme_builder_opt = None;
        self.bg_state = Default::default();
        self.xkb_config_opt = None;
        self.time_applet_config = Default::default();

        // 1. Try reading icon from AccountsService icon_file if provided
        if let Some(icon_path_str) = icon_file_opt {
            let icon_path = Path::new(icon_path_str);
            if icon_path.is_file() {
                if let Ok(mut file) = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(icon_path)
                {
                    let mut icon_data = Vec::new();
                    if let Ok(count) = file.read_to_end(&mut icon_data) {
                        icon_data.truncate(count);
                        self.icon_opt = Some(icon_data);
                    }
                }
            }
        }

        // 2. Fallback to /var/lib/AccountsService/icons/<username>
        if self.icon_opt.is_none() {
            let icon_path = Path::new("/var/lib/AccountsService/icons").join(&self.name);
            match fs::OpenOptions::new()
                .read(true)
                // Do not follow symlinks
                .custom_flags(libc::O_NOFOLLOW)
                .open(&icon_path)
            {
                Ok(mut icon_file) => {
                    let mut icon_data = Vec::new();
                    match icon_file.read_to_end(&mut icon_data) {
                        Ok(count) => {
                            icon_data.truncate(count);
                            self.icon_opt = Some(icon_data);
                        }
                        Err(err) => {
                            tracing::error!("failed to read icon data {:?}: {:?}", icon_path, err);
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!("failed to open icon {:?}: {:?}", icon_path, err);
                }
            }
        }

        let mut is_dark = true;
        match cosmic_theme::ThemeMode::config() {
            Ok(helper) => match cosmic_theme::ThemeMode::get_entry(&helper) {
                Ok(theme_mode) => {
                    is_dark = theme_mode.is_dark;
                }
                Err((errs, theme_mode)) => {
                    tracing::error!("failed to load cosmic-theme config: {:?}", errs);
                    is_dark = theme_mode.is_dark;
                }
            },
            Err(err) => {
                tracing::error!("failed to create cosmic-theme mode helper: {:?}", err);
            }
        }

        match if is_dark {
            cosmic_theme::Theme::dark_config()
        } else {
            cosmic_theme::Theme::light_config()
        } {
            Ok(helper) => match cosmic_theme::Theme::get_entry(&helper) {
                Ok(theme) => {
                    self.theme_opt = Some(theme);
                }
                Err((errs, theme)) => {
                    tracing::error!("failed to load cosmic-theme config: {:?}", errs);
                    self.theme_opt = Some(theme);
                }
            },
            Err(err) => {
                tracing::error!("failed to create cosmic-theme config helper: {:?}", err);
            }
        }

        match if is_dark {
            cosmic_theme::ThemeBuilder::dark_config()
        } else {
            cosmic_theme::ThemeBuilder::light_config()
        } {
            Ok(helper) => match cosmic_theme::ThemeBuilder::get_entry(&helper) {
                Ok(theme) => {
                    self.theme_builder_opt = Some(theme);
                }
                Err((errs, theme)) => {
                    tracing::error!("failed to load cosmic-theme builder config: {:?}", errs);
                    self.theme_builder_opt = Some(theme);
                }
            },
            Err(err) => {
                tracing::error!(
                    "failed to create cosmic-theme builder config helper: {:?}",
                    err
                );
            }
        }

        //TODO: fallback to background config if background state is not set?
        match cosmic_bg_config::state::State::state() {
            Ok(helper) => match cosmic_bg_config::state::State::get_entry(&helper) {
                Ok(state) => {
                    self.bg_state = state;
                }
                Err((errs, state)) => {
                    tracing::error!("failed to load cosmic-bg state: {:?}", errs);
                    self.bg_state = state;
                }
            },
            Err(err) => {
                tracing::error!("failed to create cosmic-bg state helper: {:?}", err);
            }
        }
        self.load_wallpapers_as_user();

        match cosmic_config::Config::new("com.system76.CosmicComp", CosmicCompConfig::VERSION) {
            Ok(config_handler) => {
                match CosmicCompConfig::get_entry(&config_handler) {
                    Ok(config) => {
                        self.xkb_config_opt = Some(config.xkb_config);
                        self.accessibility_zoom = config.accessibility_zoom;
                    }
                    Err((errs, config)) => {
                        tracing::error!("errors loading cosmic-comp config: {:?}", errs);
                        self.xkb_config_opt = Some(config.xkb_config);
                        self.accessibility_zoom = config.accessibility_zoom;
                    }
                };
            }
            Err(err) => {
                tracing::error!("failed to create cosmic-comp config handler: {}", err);
            }
        };

        let xdg = xdg::BaseDirectories::new();
        self.kdl_output_lists = xdg
            .get_state_home()
            .map(|mut s| {
                s.push("cosmic-comp/outputs.ron");
                let lists = randr::load_outputs(Some(&s));
                lists
                    .into_iter()
                    .map(|l| KdlDocument::from(l).to_string())
                    .collect()
            })
            .unwrap_or_default();

        match cosmic_config::Config::new("com.system76.CosmicAppletTime", TimeAppletConfig::VERSION)
        {
            Ok(config_handler) => match TimeAppletConfig::get_entry(&config_handler) {
                Ok(config) => {
                    self.time_applet_config = config;
                }
                Err((errs, config)) => {
                    tracing::error!("failed to load time applet config: {:?}", errs);
                    self.time_applet_config = config;
                }
            },
            Err(err) => {
                tracing::error!(
                    "failed to create CosmicAppletTime config handler: {:?}",
                    err
                );
            }
        };
    }
}

impl From<pwd::Passwd> for UserData {
    fn from(user: pwd::Passwd) -> Self {
        let mut full_name = user
            .gecos
            .as_ref()
            .and_then(|gecos| gecos.split(',').next())
            .map(|x| x.to_string())
            .unwrap_or_default();
        if full_name.is_empty() {
            full_name = user.name.clone();
        }
        Self {
            uid: user.uid,
            name: user.name.clone(),
            full_name,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user(uid: u32, name: &str, shell: &str) -> pwd::Passwd {
        pwd::Passwd {
            name: name.to_string(),
            passwd: Some("x".to_string()),
            uid,
            gid: uid,
            gecos: Some(name.to_string()),
            dir: format!("/home/{name}"),
            shell: shell.to_string(),
        }
    }

    #[test]
    fn test_user_filter() {
        let filter = UserFilter {
            uid_min: 1000,
            uid_max: 60000,
        };

        // Standard local user
        let local_user = create_test_user(1000, "alice", "/bin/bash");
        assert!(filter.filter_local(&local_user));
        assert!(filter.filter_cached(&local_user));

        // System user (< UID_MIN)
        let root_user = create_test_user(0, "root", "/bin/bash");
        assert!(!filter.filter_local(&root_user));
        assert!(!filter.filter_cached(&root_user));

        // Daemon user with nologin shell
        let daemon_user = create_test_user(1001, "daemon_acc", "/usr/sbin/nologin");
        assert!(!filter.filter_local(&daemon_user));
        assert!(!filter.filter_cached(&daemon_user));

        // Nobody account
        let nobody_user = create_test_user(65534, "nobody", "/bin/bash");
        assert!(!filter.filter_local(&nobody_user));
        assert!(!filter.filter_cached(&nobody_user));

        // Active Directory / SSSD enterprise user with high UID (e.g. 200004)
        let ad_user = create_test_user(200004, "corp_ad_user", "/bin/bash");
        assert!(!filter.filter_local(&ad_user)); // exceeds standard local UID_MAX
        assert!(filter.filter_cached(&ad_user)); // allowed for cached AD users
    }
}

