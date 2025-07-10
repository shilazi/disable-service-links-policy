extern crate kubewarden_policy_sdk as kubewarden;

use guest::prelude::*;
use k8s_openapi::api::core::v1 as apicore;
use k8s_openapi::Resource;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};
use kubewarden_policy_sdk::wapc_guest as guest;
use lazy_static::lazy_static;
use slog::{info, o, warn, Logger};

use settings::Settings;

mod settings;
lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => settings::POLICY_NAME)
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");
    if validation_request.request.dry_run {
        info!(LOG_DRAIN, "dry run mode, accepting resource");
        return kubewarden::accept_request();
    }

    if validation_request.request.kind.kind != apicore::Pod::KIND {
        warn!(LOG_DRAIN, "Policy validates Pods only. Accepting resource"; "kind" => &validation_request.request.kind.kind);
        return kubewarden::accept_request();
    }
    // pod name
    let pod_name = &validation_request.request.name;
    // namespace
    let namespace = &validation_request.request.namespace;
    // operation
    let operation = &validation_request.request.operation;
    // kind
    let kind = &validation_request.request.kind.kind;

    info!(LOG_DRAIN,  "{} {}", operation.to_lowercase(), kind, ; "name" => pod_name, "namespace" => namespace);
    if validation_request.settings.exempt(namespace, pod_name) {
        warn!(LOG_DRAIN, "accepting {} with exemption", pod_name);
        return kubewarden::accept_request();
    }

    match serde_json::from_value::<apicore::Pod>(validation_request.request.object) {
        Ok(mut pod) => {
            let pod_spec = pod.spec.as_mut().unwrap();
            pod_spec.enable_service_links = Some(false);

            let mutated_object = serde_json::to_value(pod)?;

            info!(
                LOG_DRAIN,
                "ending mutated {}/{}/{} enableServiceLinks with false", namespace, kind, pod_name,
            );
            kubewarden::mutate_request(mutated_object)
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use kubewarden_policy_sdk::test::Testcase;

    #[test]
    fn mutate_pod_enable_service_links() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        let tc = Testcase {
            name: String::from("Pod creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "Something mutated with test case: {}",
            tc.name,
        );

        let final_pod_json = serde_json::to_string_pretty(&res.mutated_object).unwrap();
        warn!(LOG_DRAIN, "{}", final_pod_json);

        let mut final_pod =
            serde_json::from_value::<apicore::Pod>(res.mutated_object.unwrap_or_default())
                .unwrap_or_default();
        assert_eq!(
            final_pod.spec.as_mut().unwrap().enable_service_links,
            Some(false),
        );

        Ok(())
    }

    #[test]
    #[allow(unused_variables)]
    fn accept_pod_enable_service_links() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";

        let exempt_namespaces = HashSet::from(["default".to_string()]);
        let exempt_pod_name_prefixes = HashSet::from(["ng".to_string()]);

        let tc = Testcase {
            name: String::from("Pod creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                // exempt_namespaces: Some(exempt_namespaces),
                // exempt_pod_name_prefixes: None,
                exempt_namespaces: None,
                exempt_pod_name_prefixes: Some(exempt_pod_name_prefixes),
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Nothing mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn mutate_deployment_enable_service_links() -> Result<(), ()> {
        let request_file = "test_data/deployment_creation.json";
        let tc = Testcase {
            name: String::from("Deployment creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Nothing mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
