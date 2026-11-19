//! Secret profiles/QRs only cross subprocess pipes and encrypted artifact files.
use anyhow::{bail, Result};
use shadowborn_core::{valid_name, State};

pub struct Enrollment {
    pub profile: Vec<u8>,
    pub qr: Option<Vec<u8>>,
}

/// Mutate only the caller's uncommitted state. Failure must never authorize a peer.
/// The client private key is deliberately not part of persistent State.
pub fn issue(
    state: &mut State,
    name: &str,
    recipient: &str,
    qr: bool,
    nat_keepalive: bool,
) -> Result<Enrollment> {
    crate::validate_recipient(recipient)?;
    state.validate()?;
    if !valid_name(name) || state.peers.iter().any(|p| p.name == name) {
        bail!("invalid or duplicate peer name")
    }
    let private = crate::generate_key(false)?;
    let mut proposed = state.clone();
    proposed.add(
        name.into(),
        crate::public_key(&private)?,
        crate::generate_key(true)?,
    )?;
    let profile = shadowborn_core::with_nat_keepalive(
        shadowborn_core::client_profile(&proposed, name, &private)?,
        nat_keepalive,
    );
    let encrypted = Enrollment {
        profile: crate::encrypt(recipient, profile.as_bytes())?,
        qr: if qr {
            // No plaintext file, shell, argv payload, terminal rendering or web API.
            let png = crate::run(
                "qrencode",
                &[
                    "-8", "-l", "M", "-s", "8", "-m", "4", "-t", "PNG", "-o", "-",
                ],
                profile.as_bytes(),
            )?;
            if !png.starts_with(b"\x89PNG\r\n\x1a\n") {
                bail!("QR tool returned an invalid image")
            }
            Some(crate::encrypt(recipient, &png)?)
        } else {
            None
        },
    };
    *state = proposed;
    Ok(encrypted)
}
