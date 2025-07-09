use kubewarden::logging;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use slog::{info, o, warn, Logger};

// Log prefix for policy server of this policy.
pub(crate) const POLICY_NAME: &str = "disable-service-links-policy";

lazy_static! {
    static ref LOG_DRAIN: Logger =
        Logger::root(logging::KubewardenDrain::new(), o!("policy" => POLICY_NAME));
}

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");
        warn!(LOG_DRAIN, "has no settings");
        warn!(LOG_DRAIN, "settings validates");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings() -> Result<(), ()> {
        let settings = Settings {};

        assert!(settings.validate().is_ok());
        Ok(())
    }
}
