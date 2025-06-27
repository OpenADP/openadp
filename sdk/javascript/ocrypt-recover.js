#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'fs';
import { createInterface } from 'readline';
import { recover } from './src/ocrypt.js';

const program = new Command();

program
    .name('ocrypt-recover')
    .description('Recover a long-term secret using Ocrypt distributed cryptography.')
    .option('--metadata <string>', 'Metadata blob from registration (required)')
    .option('--password <string>', 'Password/PIN to unlock the secret (will prompt if not provided)')
    .option('--servers-url <string>', 'Custom URL for server registry (empty uses default)', '')
    .option('--output <string>', 'File to write recovery result JSON (writes to stdout if not specified)')
    .option('--help', 'Show help message')
    .addHelpText('after', `
Examples:
  ocrypt-recover --metadata '{"servers":[...]}'
  ocrypt-recover --metadata "$(cat metadata.json)" --output result.json
  ocrypt-recover --metadata "$(cat metadata.json)" --password mypin`);

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
        
        // Call ocrypt.recover
        const result = await recover(metadataBytes, pin, options.serversUrl);
        
        // Create JSON tuple output (matching Go structure)
        const output = {
            secret: new TextDecoder().decode(result.secret),
            remaining_guesses: result.remaining,
            updated_metadata: new TextDecoder().decode(result.updatedMetadata)
        };
        
        const outputJson = JSON.stringify(output);
        
        // Output result as JSON
        if (options.output) {
            // Write to file
            writeFileSync(options.output, outputJson);
            console.error(`✅ Recovery result written to ${options.output}`);
        } else {
            // Write to stdout
            console.log(outputJson);
        }
        
    } catch (error) {
        console.error(`Recovery failed: ${error.message}`);
        process.exit(1);
    }
}

main(); 