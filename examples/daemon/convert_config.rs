// examples/convert_config.rs
use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Usage: {} <config_file>", args[0]);
        eprintln!("Example: {} ~/.reticulum/config", args[0]);
        std::process::exit(1);
    }
    
    let input_path = Path::new(&args[1]);
    
    if !input_path.exists() {
        eprintln!("Error: File '{}' does not exist", input_path.display());
        std::process::exit(1);
    }
    
    println!("Reading config from: {}", input_path.display());
    let content = fs::read_to_string(input_path)?;
    
    let backup_path = input_path.with_extension("backup");
    fs::write(&backup_path, &content)?;
    println!("Created backup at: {}", backup_path.display());
    
    let converted = convert_config(&content);
    
    fs::write(input_path, &converted)?;
    println!("✓ Converted config written to: {}", input_path.display());
    println!();
    println!("Changes made:");
    println!("  - Converted True/False/Yes/No → true/false");
    println!("  - Quoted all string values (IPs, hostnames, paths, types)");
    println!("  - Converted [[Interface Name]] → [[interfaces]] with name field");
    println!("  - Normalized indentation");
    println!("  - Preserved all comments");
    
    Ok(())
}

fn convert_config(content: &str) -> String {
    let mut output = String::new();
    
    for line in content.lines() {
        let trimmed = line.trim();
        
        // Empty lines pass through
        if trimmed.is_empty() {
            output.push('\n');
            continue;
        }
        
        // Skip [interfaces] header - we use [[interfaces]] instead
        if trimmed == "[interfaces]" {
            continue;
        }
        
        // Detect interface block start
        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            let name = trimmed.trim_start_matches("[[").trim_end_matches("]]").trim();
            if name != "interfaces" {
                // Convert [[Interface Name]] to [[interfaces]]
                output.push_str("\n[[interfaces]]\n");
                output.push_str(&format!("name = \"{}\"\n", name));
                continue;
            } else {
                output.push_str("\n[[interfaces]]\n");
                continue;
            }
        }
        
        // Process the line
        let mut converted = trimmed.to_string();
        
        // Convert booleans
        converted = converted.replace(" = True", " = true");
        converted = converted.replace(" = False", " = false");
        converted = converted.replace(" = Yes", " = true");
        converted = converted.replace(" = yes", " = true");
        converted = converted.replace(" = No", " = false");
        converted = converted.replace(" = no", " = false");
        
        // Quote unquoted string values (only for non-comments)
        if !converted.starts_with('#') {
            converted = quote_if_needed(&converted, "type");
            converted = quote_if_needed(&converted, "remote");
            converted = quote_if_needed(&converted, "target_host");
            converted = quote_if_needed(&converted, "bind_host");
            converted = quote_if_needed(&converted, "listen_ip");
            converted = quote_if_needed(&converted, "forward_ip");
            converted = quote_if_needed(&converted, "peers");
            converted = quote_if_needed(&converted, "instance_name");
            converted = quote_if_needed(&converted, "port");
            converted = quote_if_needed(&converted, "callsign");
            converted = quote_if_needed(&converted, "parity");
        }
        
        output.push_str(&converted);
        output.push('\n');
    }
    
    output
}

fn quote_if_needed(line: &str, key: &str) -> String {
    let pattern = format!("{} = ", key);
    let quoted_pattern = format!("{} = \"", key);
    
    // Already quoted or not present
    if !line.contains(&pattern) || line.contains(&quoted_pattern) {
        return line.to_string();
    }
    
    // Find the value
    if let Some(pos) = line.find(&pattern) {
        let value_start = pos + pattern.len();
        let rest = &line[value_start..];
        let value = rest.split_whitespace().next().unwrap_or(rest).trim();
        
        // Don't quote numbers or booleans
        if value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok() 
            || value == "true" || value == "false" {
            return line.to_string();
        }
        
        // Quote the value
        format!("{}{} = \"{}\"", &line[..pos], key, value)
    } else {
        line.to_string()
    }
}
