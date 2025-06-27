#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'fs';
import { createInterface } from 'readline';
import { register } from './src/ocrypt.js';

const program = new Command();

program
    .name('ocrypt-register')
    .description('Register a long-term secret using Ocrypt distributed cryptography.')
    .option('--user-id <string>', 'Unique identifier for the user (required)')
    .option('--app-id <string>', 'Application identifier to namespace secrets per app (required)')
    .option('--long-term-secret <string>', 'Long-term secret to protect (required)')
    .option('--password <string>', 'Password/PIN to unlock the secret (will prompt if not provided)')
    .option('--max-guesses <number>', 'Maximum wrong PIN attempts before lockout', '10')
    .option('--servers-url <string>', 'Custom URL for server registry (empty uses default)', '')
    .option('--output <string>', 'File to write metadata JSON (writes to stdout if not specified)')
    .option('--help', 'Show help message')
    .addHelpText('after', `
Examples:
  ocrypt-register --user-id alice@example.com --app-id myapp --long-term-secret "my secret key"
  ocrypt-register --user-id alice@example.com --app-id myapp --long-term-secret "my secret key" --output metadata.json`);

program.parse();

const options = program.opts();

// Show help if requested
if (options.help) {
    program.help();
}

// Validate required parameters
if (!options.userId) {
    console.error('Error: --user-id is required');
    program.help();
    process.exit(1);
}
if (!options.appId) {
    console.error('Error: --app-id is required');
    program.help();
    process.exit(1);
}
if (!options.longTermSecret) {
    console.error('Error: --long-term-secret is required');
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
        
        // Convert long-term secret to bytes
        const longTermSecretBytes = new TextEncoder().encode(options.longTermSecret);
        
        // Call ocrypt.register
        const metadata = await register(
            options.userId,
            options.appId,
            longTermSecretBytes,
            pin,
            parseInt(options.maxGuesses),
            options.serversUrl
        );
        
        // Output metadata as JSON
        if (options.output) {
            // Write to file
            writeFileSync(options.output, metadata);
            console.error(`✅ Metadata written to ${options.output}`);
        } else {
            // Write to stdout
            console.log(new TextDecoder().decode(metadata));
        }
        
    } catch (error) {
        console.error(`Registration failed: ${error.message}`);
        process.exit(1);
    }
}

main(); 