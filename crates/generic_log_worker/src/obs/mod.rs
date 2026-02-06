pub mod logs;
pub mod metrics;

#[derive(Clone)]
pub struct Wshim {
    token: String,
    socket: worker::Fetcher,
}

pub trait WshimData {
    fn endpoint() -> &'static str;
    fn to_body(&self) -> Vec<u8>;
}

impl Wshim {
    /// Return an instance of `Wshim` initialized from environment variables.
    ///
    /// # Errors
    ///
    /// Will return an error if the `WSHIM_TOKEN` environment variable is not
    /// set, or if the `WSHIM_SOCKET` binding is not available.
    pub fn from_env(env: &worker::Env) -> worker::Result<Self> {
        Ok(Self {
            token: env.var("WSHIM_TOKEN")?.to_string(),
            socket: env.get_binding("WSHIM_SOCKET")?,
        })
    }

    pub async fn flush<E: WshimData>(&self, data: E) {
        let fetch_result = self
            .socket
            .fetch(
                format!("https://workers-logging.cfdata.org/{}", E::endpoint()),
                Some(worker::RequestInit {
                    method: worker::Method::Post,
                    headers: worker::Headers::from_iter([(
                        "Authorization".to_owned(),
                        format!("Bearer: {}", self.token),
                    )]),
                    body: Some(data.to_body().into()),
                    ..Default::default()
                }),
            )
            .await;
        let response = match fetch_result {
            Ok(response) => response,
            Err(e) => {
                worker::console_error!("failed to post to wshim /{}: {e:?}", E::endpoint());
                return;
            }
        };
        if response.status_code() != 200 {
            worker::console_error!(
                "post to wshim /{} failed with status code: {}",
                E::endpoint(),
                response.status_code()
            );
        }
    }
}
