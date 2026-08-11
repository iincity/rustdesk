/// Stable identity snapshot shared by all NexusFlow client capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceIdentity {
    pub rustdesk_id: String,
    pub device_uid: Option<String>,
}

impl DeviceIdentity {
    pub fn from_rustdesk_id(rustdesk_id: impl Into<String>) -> Self {
        Self {
            rustdesk_id: rustdesk_id.into(),
            device_uid: None,
        }
    }

    pub fn bind_device_uid(&mut self, device_uid: impl Into<String>) {
        self.device_uid = Some(device_uid.into());
    }
}
