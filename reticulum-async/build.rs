use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto/");

    // Generate proto files for Kaonic
    tonic_build::configure()
        .type_attribute(
            "ConfigurationRequest",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "RadioPhyConfigFSK",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "RadioPhyConfigOFDM",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "kaonic.ConfigurationRequest.phy_config",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "kaonic.ConfigurationRequest.phy_config",
            "#[serde(tag = \"type\", content = \"data\")]",
        )
        .compile_protos(
            &["proto/kaonic/kaonic.proto"],
            &["proto/kaonic"], // The directory containing your proto files
        )?;
    Ok(())
}
