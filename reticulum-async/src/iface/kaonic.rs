use kaonic_grpc::proto::ConfigurationRequest;

pub mod kaonic_grpc;

pub const RADIO_FRAME_MAX_SIZE: usize = 2048usize;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RadioModule {
    RadioA = 0x00,
    RadioB = 0x01,
}

pub type RadioConfig = ConfigurationRequest;

impl RadioConfig {
    pub fn new_for_module(module: RadioModule) -> Self {
        Self {
            module: module as i32,
            freq: 869535,
            channel: 11,
            channel_spacing: 200,
            tx_power: 10,
            phy_config: Some(kaonic_grpc::proto::configuration_request::PhyConfig::Ofdm(
                kaonic_grpc::proto::RadioPhyConfigOfdm { mcs: 6, opt: 0 },
            )),
        }
    }
}
