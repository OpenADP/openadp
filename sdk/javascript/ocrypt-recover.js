#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync, writeFileSync, existsSync, renameSync } from 'fs';
import { createInterface } from 'readline';
import { recoverAndReregister } from './src/ocrypt.js';

const program = new Command();

program
    .name('ocrypt-recover')
    .description(`Recover a long-term secret and reregister with fresh cryptographic material.

This tool performs two steps:
1. Recovers the secret from existing metadata
2. Reregisters with completely fresh cryptographic material

The recovered secret is printed to stderr for verification, and the new metadata
is written to the specified output file (or stdout).`)
    .option('--metadata <string>', 'Metadata blob from registration (required)')
    .option('--password <string>', 'Password/PIN to unlock the secret (will prompt if not provided)')
    .option('--servers-url <string>', 'Custom URL for server registry (default: https://servers.openadp.org/api/servers.json)', '')
    .option('--output <string>', 'File to write new metadata to (writes to stdout if not specified)')
    .option('--test-mode', 'Enable test mode (outputs JSON with secret and metadata)')
    .option('--help', 'Show help message')
    .addHelpText('after', `
Examples:
  ocrypt-recover --metadata '{"servers":[...]}' --password mypin
  ocrypt-recover --metadata "$(cat metadata.json)" --output metadata.json  
  ocrypt-recover --metadata "$(cat old_metadata.json)" --output new_metadata.json

Default servers URL: https://servers.openadp.org/api/servers.json

The tool automatically backs up existing files by renaming them with .old extension.`);

program.parse();

const options = program.opts();

// Show help if requested
if (options.help) {
    program.help();
}

// Validate required parameters
if (!options.metadata) {
    console.error('Error: --metadata is required');
    program.help();
    process.exit(1);
}

/**
 * Safely write data to a file, backing up existing file first.
 */
function safeWriteFile(filename, data) {
    // Check if file exists
    if (existsSync(filename)) {
        // File exists, create backup
        const backupName = filename + ".old";
        console.error(`📋 Backing up existing ${filename} to ${backupName}`);
        
        try {
            renameSync(filename, backupName);
            console.error(`✅ Backup created: ${backupName}`);
        } catch (error) {
            throw new Error(`Failed to backup existing file: ${error.message}`);
        }
    }
    
    // Write new file
    try {
        writeFileSync(filename, data);
        console.error(`✅ New metadata written to: ${filename}`);
    } catch (error) {
        throw new Error(`Failed to write file: ${error.message}`);
    }
}

async function getPassword() {
    if (options.password) {
        return options.password;
    }
    
    // Prompt for password
    const rl = createInterface({
        input: process.stdin,
        output: process.stderr
    });
    
    return new Promise((resolve, reject) => {
        rl.question('Password: ', (password) => {
            rl.close();
            if (!password) {
                console.error('Error: password cannot be empty');
                process.exit(1);
            }
            resolve(password);
        });
        
        // Hide password input
        rl._writeToOutput = function _writeToOutput(stringToWrite) {
            if (rl.stdoutMuted) {
                rl.output.write('*');
            } else {
                rl.output.write(stringToWrite);
            }
        };
        rl.stdoutMuted = true;
    });
}

async function main() {
    try {
        const pin = await getPassword();
        
        // Convert metadata to bytes
        const metadataBytes = new TextEncoder().encode(options.metadata);
        
        // Use default servers URL if none provided
        const serversUrl = options.serversUrl || "https://servers.openadp.org/api/servers.json";
        
        // Call ocrypt.recoverAndReregister
        console.error('🔄 Starting recovery and re-registration...');
        const result = await recoverAndReregister(metadataBytes, pin, serversUrl);
        
        // Handle test mode
        if (options.testMode) {
            const secretStr = new TextDecoder().decode(result.secret);
            const newMetadataStr = new TextDecoder().decode(result.newMetadata);
            
            const testResult = {
                secret: secretStr,
                new_metadata: newMetadataStr
            };
            
            console.log(JSON.stringify(testResult));
            return;
        }
        
        // Normal mode: Print recovered secret to stderr for verification
        const secretStr = new TextDecoder().decode(result.secret);
        console.error(`🔓 Recovered secret: ${secretStr}`);
        
        // Convert new metadata to string
        const newMetadataStr = new TextDecoder().decode(result.newMetadata);
        
        // Output new metadata
        if (options.output) {
            // Write to file with backup
            safeWriteFile(options.output, newMetadataStr);
        } else {
            // Write to stdout
            console.log(newMetadataStr);
        }
        
        console.error('✅ Recovery and re-registration complete!');
        console.error('📝 New metadata contains completely fresh cryptographic material');
        
    } catch (error) {
        console.error(`❌ Recovery failed: ${error.message}`);
        process.exit(1);
    }
}

main(); 