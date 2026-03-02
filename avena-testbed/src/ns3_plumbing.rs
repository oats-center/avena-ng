use thiserror::Error;
use tokio::process::Command;

pub const IFACE_NAME_MAX_LEN: usize = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ns3EndpointNames {
    pub ns_if: String,
    pub root_if: String,
    pub tap_if: String,
    pub bridge_if: String,
}

impl Ns3EndpointNames {
    #[must_use]
    pub fn from_ids(network_id: &str, node_id: &str, radio_id: &str) -> Self {
        let suffix = hash8(network_id, node_id, radio_id);
        Self {
            ns_if: format!("n{suffix}"),
            root_if: format!("r{suffix}"),
            tap_if: format!("t{suffix}"),
            bridge_if: format!("b{suffix}"),
        }
    }

    pub fn validate(&self) -> Result<(), Ns3PlumbingError> {
        for name in [&self.ns_if, &self.root_if, &self.tap_if, &self.bridge_if] {
            if name.len() > IFACE_NAME_MAX_LEN {
                return Err(Ns3PlumbingError::InterfaceNameTooLong {
                    name: name.clone(),
                    max_len: IFACE_NAME_MAX_LEN,
                });
            }
        }

        Ok(())
    }
}

fn hash8(network_id: &str, node_id: &str, radio_id: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for part in [network_id.as_bytes(), &[0], node_id.as_bytes(), &[0], radio_id.as_bytes()] {
        for byte in part {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
    }

    format!("{:08x}", (hash & 0xffff_ffff) as u32)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub allow_failure: bool,
}

impl PlannedCommand {
    #[must_use]
    pub fn required(program: &str, args: &[String]) -> Self {
        Self {
            program: program.to_string(),
            args: args.to_vec(),
            allow_failure: false,
        }
    }

    #[must_use]
    pub fn best_effort(program: &str, args: &[String]) -> Self {
        Self {
            program: program.to_string(),
            args: args.to_vec(),
            allow_failure: true,
        }
    }

    #[must_use]
    pub fn display(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

#[derive(Error, Debug)]
pub enum Ns3PlumbingError {
    #[error("interface name '{name}' exceeds IFNAMSIZ ({max_len})")]
    InterfaceNameTooLong { name: String, max_len: usize },

    #[error("command failed: {cmd}: {message}")]
    CommandFailed { cmd: String, message: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[must_use]
pub fn endpoint_setup_plan(names: &Ns3EndpointNames, node_pid: u32) -> Vec<PlannedCommand> {
    let mut plan = endpoint_setup_plan_root_only(names);
    plan.insert(4, attach_ns_interface_to_pid_plan(names, node_pid));
    plan
}

#[must_use]
pub fn endpoint_setup_plan_root_only(names: &Ns3EndpointNames) -> Vec<PlannedCommand> {
    vec![
        PlannedCommand::best_effort(
            "ip",
            &[
                "link".to_string(),
                "del".to_string(),
                names.root_if.clone(),
            ],
        ),
        PlannedCommand::best_effort(
            "ip",
            &[
                "link".to_string(),
                "del".to_string(),
                names.bridge_if.clone(),
            ],
        ),
        PlannedCommand::best_effort(
            "ip",
            &[
                "tuntap".to_string(),
                "del".to_string(),
                "dev".to_string(),
                names.tap_if.clone(),
                "mode".to_string(),
                "tap".to_string(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "add".to_string(),
                names.root_if.clone(),
                "type".to_string(),
                "veth".to_string(),
                "peer".to_string(),
                "name".to_string(),
                names.ns_if.clone(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "add".to_string(),
                names.bridge_if.clone(),
                "type".to_string(),
                "bridge".to_string(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "tuntap".to_string(),
                "add".to_string(),
                "dev".to_string(),
                names.tap_if.clone(),
                "mode".to_string(),
                "tap".to_string(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "set".to_string(),
                names.root_if.clone(),
                "master".to_string(),
                names.bridge_if.clone(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "set".to_string(),
                names.tap_if.clone(),
                "master".to_string(),
                names.bridge_if.clone(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "set".to_string(),
                names.bridge_if.clone(),
                "up".to_string(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "set".to_string(),
                names.root_if.clone(),
                "up".to_string(),
            ],
        ),
        PlannedCommand::required(
            "ip",
            &[
                "link".to_string(),
                "set".to_string(),
                names.tap_if.clone(),
                "up".to_string(),
            ],
        ),
    ]
}

#[must_use]
pub fn attach_ns_interface_to_pid_plan(names: &Ns3EndpointNames, node_pid: u32) -> PlannedCommand {
    PlannedCommand::required(
        "ip",
        &[
            "link".to_string(),
            "set".to_string(),
            names.ns_if.clone(),
            "netns".to_string(),
            node_pid.to_string(),
        ],
    )
}

#[must_use]
pub fn endpoint_teardown_plan(names: &Ns3EndpointNames) -> Vec<PlannedCommand> {
    vec![
        PlannedCommand::best_effort(
            "ip",
            &[
                "link".to_string(),
                "del".to_string(),
                names.bridge_if.clone(),
            ],
        ),
        PlannedCommand::best_effort(
            "ip",
            &[
                "link".to_string(),
                "del".to_string(),
                names.root_if.clone(),
            ],
        ),
        PlannedCommand::best_effort(
            "ip",
            &[
                "tuntap".to_string(),
                "del".to_string(),
                "dev".to_string(),
                names.tap_if.clone(),
                "mode".to_string(),
                "tap".to_string(),
            ],
        ),
    ]
}

pub async fn apply_plan(plan: &[PlannedCommand]) -> Result<(), Ns3PlumbingError> {
    for step in plan {
        let output = Command::new(&step.program).args(&step.args).output().await?;
        if !output.status.success() && !step.allow_failure {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Ns3PlumbingError::CommandFailed {
                cmd: step.display(),
                message: stderr.trim().to_string(),
            });
        }
    }

    Ok(())
}

pub async fn setup_endpoint_port(
    names: &Ns3EndpointNames,
    node_pid: u32,
) -> Result<(), Ns3PlumbingError> {
    names.validate()?;
    let plan = endpoint_setup_plan(names, node_pid);
    apply_plan(&plan).await
}

pub async fn teardown_endpoint_port(names: &Ns3EndpointNames) -> Result<(), Ns3PlumbingError> {
    names.validate()?;
    let plan = endpoint_teardown_plan(names);
    apply_plan(&plan).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_names_are_deterministic_and_short() {
        let a = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");
        let b = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");

        assert_eq!(a, b);

        for name in [&a.ns_if, &a.root_if, &a.tap_if, &a.bridge_if] {
            assert!(name.len() <= IFACE_NAME_MAX_LEN, "name too long: {name}");
        }

        assert!(a.ns_if.starts_with('n'));
        assert!(a.root_if.starts_with('r'));
        assert!(a.tap_if.starts_with('t'));
        assert!(a.bridge_if.starts_with('b'));
    }

    #[test]
    fn derived_names_change_with_radio_id() {
        let first = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");
        let second = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi1");

        assert_ne!(first, second);
    }

    #[test]
    fn setup_plan_contains_expected_sequence() {
        let names = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");
        let plan = endpoint_setup_plan(&names, 4242);

        assert_eq!(plan.len(), 12);

        assert_eq!(plan[0].display(), format!("ip link del {}", names.root_if));
        assert!(plan[0].allow_failure);

        assert_eq!(plan[1].display(), format!("ip link del {}", names.bridge_if));
        assert!(plan[1].allow_failure);

        assert_eq!(
            plan[2].display(),
            format!("ip tuntap del dev {} mode tap", names.tap_if)
        );
        assert!(plan[2].allow_failure);

        assert_eq!(
            plan[3].display(),
            format!(
                "ip link add {} type veth peer name {}",
                names.root_if, names.ns_if
            )
        );
        assert!(!plan[3].allow_failure);

        assert_eq!(
            plan[4].display(),
            format!("ip link set {} netns 4242", names.ns_if)
        );
        assert!(!plan[4].allow_failure);

        assert_eq!(
            plan[5].display(),
            format!("ip link add {} type bridge", names.bridge_if)
        );
        assert!(!plan[5].allow_failure);

        assert_eq!(
            plan[6].display(),
            format!("ip tuntap add dev {} mode tap", names.tap_if)
        );
        assert!(!plan[6].allow_failure);

        assert_eq!(
            plan[7].display(),
            format!("ip link set {} master {}", names.root_if, names.bridge_if)
        );
        assert!(!plan[7].allow_failure);

        assert_eq!(
            plan[8].display(),
            format!("ip link set {} master {}", names.tap_if, names.bridge_if)
        );
        assert!(!plan[8].allow_failure);

        assert_eq!(
            plan[9].display(),
            format!("ip link set {} up", names.bridge_if)
        );
        assert!(!plan[9].allow_failure);

        assert_eq!(
            plan[10].display(),
            format!("ip link set {} up", names.root_if)
        );
        assert!(!plan[10].allow_failure);

        assert_eq!(
            plan[11].display(),
            format!("ip link set {} up", names.tap_if)
        );
        assert!(!plan[11].allow_failure);
    }

    #[test]
    fn teardown_plan_is_best_effort() {
        let names = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");
        let plan = endpoint_teardown_plan(&names);

        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|step| step.allow_failure));
        assert_eq!(plan[0].display(), format!("ip link del {}", names.bridge_if));
        assert_eq!(plan[1].display(), format!("ip link del {}", names.root_if));
        assert_eq!(
            plan[2].display(),
            format!("ip tuntap del dev {} mode tap", names.tap_if)
        );
    }

    #[test]
    fn validate_rejects_long_interface_names() {
        let names = Ns3EndpointNames {
            ns_if: "n1234567890123456".to_string(),
            root_if: "rshort".to_string(),
            tap_if: "tshort".to_string(),
            bridge_if: "bshort".to_string(),
        };

        let err = names.validate().unwrap_err();
        assert!(err.to_string().contains("exceeds IFNAMSIZ"));
    }

    #[test]
    fn setup_root_only_plan_has_no_netns_move_step() {
        let names = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");
        let plan = endpoint_setup_plan_root_only(&names);

        assert_eq!(plan.len(), 11);
        assert!(plan.iter().all(|step| !step.args.iter().any(|arg| arg == "netns")));
        assert_eq!(
            plan[3].display(),
            format!(
                "ip link add {} type veth peer name {}",
                names.root_if, names.ns_if
            )
        );
    }

    #[test]
    fn attach_plan_moves_ns_interface_to_pid() {
        let names = Ns3EndpointNames::from_ids("ab-wifi", "nodeA", "wifi0");
        let step = attach_ns_interface_to_pid_plan(&names, 1234);

        assert_eq!(step.display(), format!("ip link set {} netns 1234", names.ns_if));
        assert!(!step.allow_failure);
    }
}
