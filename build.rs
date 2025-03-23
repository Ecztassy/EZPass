use std::fs::File;
use std::io::BufWriter;
use image::{self, ImageFormat, imageops};
use slint_build;
use embed_resource;
<<<<<<< HEAD

fn main() {
    // Compile the Slint UI file
    slint_build::compile("ui/app-window.slint").expect("Slint build failed");
=======
use slint_build::CompilerConfiguration;



fn main() {
    // Compile the Slint UI file
    let config = CompilerConfiguration::new()
        .with_style("cosmic-dark".into());
    slint_build::compile_with_config("ui/app-window.slint", config).expect("Slint build failed");


>>>>>>> bd9a5f0 (final version)

    // Convert PNG to ICO
    let png_path = "ui/icon/icon.png";
    let ico_path = "ui/icon/icon.ico";

    // Open the PNG image
    let img = image::open(png_path).expect("Failed to open PNG icon at ui/icon/icon.png");

    // Resize the image to 256x256 (max ICO size) if it’s larger
    let resized_img = if img.width() > 256 || img.height() > 256 {
        imageops::resize(&img, 256, 256, imageops::FilterType::Lanczos3)
    } else {
        img.to_rgba8() // Convert to RGBA if not resizing
    };

    // Create ICO file and write the resized image
    let mut ico_file = BufWriter::new(File::create(ico_path).expect("Failed to create ICO file at ui/icon/icon.ico"));
    resized_img
        .write_to(&mut ico_file, ImageFormat::Ico)
        .expect("Failed to convert resized PNG to ICO");

    // Embed the Windows resource (icon)
    let _ = embed_resource::compile("ezpass.rc", embed_resource::NONE);
}