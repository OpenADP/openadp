// Ghost Notes - Main Application Logic
// Local-only version with encrypted storage

class GhostNotesApp {
    constructor() {
        this.currentScreen = 'login';
        this.sessionKey = null;
        this.decryptedNotes = new Map();
        this.sessionActive = false;
        this.currentNoteId = null;
        this.autoLockTimer = null;
        this.sessionWarningTimer = null;
        this.settings = this.loadSettings();
        
        // Initialize the app
        this.init();
    }

    async init() {
        console.log('🎭 Initializing Ghost Notes...');
        
        // Check if app is already set up
        const isSetup = this.checkIfSetup();
        
        if (!isSetup) {
            this.showScreen('setup');
        } else {
            this.showScreen('login');
        }
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Set up PWA features
        this.setupPWA();
        
        console.log('👻 Ghost Notes ready!');
    }

    checkIfSetup() {
        return localStorage.getItem('ghost_notes_setup') === 'true';
    }

    loadSettings() {
        const defaultSettings = {
            maxGuesses: 10,
            autoLockTimeout: 300000, // 5 minutes
            sessionWarningTime: 30000, // 30 seconds
            currentGuesses: 0,
            userID: null,
            encryptionSalt: null
        };
        
        const saved = localStorage.getItem('ghost_notes_settings');
        return saved ? { ...defaultSettings, ...JSON.parse(saved) } : defaultSettings;
    }

    saveSettings() {
        localStorage.setItem('ghost_notes_settings', JSON.stringify(this.settings));
    }

    showScreen(screenName) {
        // Hide all screens
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.remove('active');
        });
        
        // Show target screen
        const targetScreen = document.getElementById(`${screenName}-screen`);
        if (targetScreen) {
            targetScreen.classList.add('active');
            this.currentScreen = screenName;
        }
    }

    setupEventListeners() {
        // Login screen
        document.getElementById('unlock-btn').addEventListener('click', () => this.handleUnlock());
        document.getElementById('pin-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleUnlock();
        });
        document.getElementById('setup-btn').addEventListener('click', () => this.showScreen('setup'));
        
        // Setup screen
        document.getElementById('create-vault-btn').addEventListener('click', () => this.handleSetup());
        document.getElementById('cancel-setup-btn').addEventListener('click', () => this.showScreen('login'));
        
        // App screen
        document.getElementById('lock-now-btn').addEventListener('click', () => this.endSession());
        document.getElementById('new-note-btn').addEventListener('click', () => this.createNewNote());
        document.getElementById('save-note-btn').addEventListener('click', () => this.saveCurrentNote());
        document.getElementById('delete-note-btn').addEventListener('click', () => this.deleteCurrentNote());
        
        // Session warning modal
        document.getElementById('extend-session-btn').addEventListener('click', () => this.extendSession());
        document.getElementById('lock-immediately-btn').addEventListener('click', () => this.endSession());
        
        // Auto-save on content change
        document.getElementById('note-title').addEventListener('input', () => this.autoSaveNote());
        document.getElementById('note-content').addEventListener('input', () => this.autoSaveNote());
        
        // Activity monitoring for auto-lock
        this.setupActivityMonitoring();
        
        // Page visibility for auto-lock
        document.addEventListener('visibilitychange', () => {
            if (document.hidden && this.sessionActive) {
                this.scheduleAutoLock(5000); // 5 seconds grace period
            } else if (!document.hidden && this.sessionActive) {
                this.cancelAutoLock();
                this.resetActivityTimer();
            }
        });
    }

    setupActivityMonitoring() {
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'touchmove'];
        events.forEach(event => {
            document.addEventListener(event, () => {
                if (this.sessionActive) {
                    this.resetActivityTimer();
                }
            }, { passive: true });
        });
    }

    async handleSetup() {
        const pin = document.getElementById('setup-pin').value;
        const confirmPin = document.getElementById('confirm-pin').value;
        const maxGuesses = parseInt(document.getElementById('max-guesses').value);
        const autoLockTimeout = parseInt(document.getElementById('auto-lock').value) * 1000;
        
        if (!pin || pin.length < 4) {
            this.showError('PIN must be at least 4 characters');
            return;
        }
        
        if (pin !== confirmPin) {
            this.showError('PINs do not match');
            return;
        }
        
        try {
            this.showLoading('Setting up your secure vault...');
            
            // Generate encryption salt
            const encryptionSalt = crypto.getRandomValues(new Uint8Array(32));
            
            // Update settings
            this.settings.maxGuesses = maxGuesses;
            this.settings.autoLockTimeout = autoLockTimeout;
            this.settings.encryptionSalt = Array.from(encryptionSalt);
            this.settings.currentGuesses = 0;
            
            this.saveSettings();
            
            // Create initial session key from PIN
            this.sessionKey = await this.deriveSessionKey(pin);
            
            // Create verification data
            await this.createVerificationData(this.sessionKey);
            
            // Mark as set up
            localStorage.setItem('ghost_notes_setup', 'true');
            
            // Create welcome note
            await this.createWelcomeNote();
            await this.saveEncryptedNotes();
            
            this.hideLoading();
            this.showScreen('login');
            this.showTemporaryMessage('Vault created successfully!');
            
        } catch (error) {
            this.hideLoading();
            this.showError('Failed to create vault: ' + error.message);
        }
    }

    async handleUnlock() {
        const pin = document.getElementById('pin-input').value;
        
        if (!pin) {
            this.showError('Please enter your PIN');
            return;
        }
        
        if (this.settings.currentGuesses >= this.settings.maxGuesses) {
            this.showError('Account locked - too many failed attempts');
            return;
        }
        
        try {
            this.showLoading('Unlocking your notes...');
            
            const sessionKey = await this.deriveSessionKey(pin);
            const isValid = await this.validateSessionKey(sessionKey);
            
            if (isValid) {
                this.settings.currentGuesses = 0;
                this.saveSettings();
                
                await this.startSession(sessionKey);
                
                this.hideLoading();
                this.showScreen('app');
                
            } else {
                this.settings.currentGuesses++;
                this.saveSettings();
                
                const remaining = this.settings.maxGuesses - this.settings.currentGuesses;
                this.hideLoading();
                this.showError(`Invalid PIN. ${remaining} attempts remaining.`);
                this.updateAttemptsDisplay();
            }
            
        } catch (error) {
            this.hideLoading();
            this.showError('Failed to unlock: ' + error.message);
        }
        
        document.getElementById('pin-input').value = '';
    }

    async deriveSessionKey(pin) {
        const encoder = new TextEncoder();
        const pinData = encoder.encode(pin);
        const saltData = new Uint8Array(this.settings.encryptionSalt);
        
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            pinData,
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );
        
        const sessionKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltData,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        return sessionKey;
    }

    async validateSessionKey(sessionKey) {
        try {
            const testData = localStorage.getItem('ghost_notes_verify');
            if (!testData) return false;
            
            const encrypted = JSON.parse(testData);
            const decrypted = await this.decryptData(encrypted, sessionKey);
            
            return decrypted === 'ghost_notes_verification';
        } catch (error) {
            return false;
        }
    }

    async createVerificationData(sessionKey) {
        const encrypted = await this.encryptData('ghost_notes_verification', sessionKey);
        localStorage.setItem('ghost_notes_verify', JSON.stringify(encrypted));
    }

    async startSession(sessionKey) {
        this.sessionKey = sessionKey;
        this.sessionActive = true;
        
        await this.loadDecryptedNotes();
        this.updateNotesListUI();
        
        console.log('🔓 Session started successfully');
    }

    async endSession() {
        console.log('🔒 Ending session...');
        
        this.showLoading('Securing your notes...');
        
        if (this.currentNoteId) {
            await this.saveCurrentNote();
        }
        
        await this.saveEncryptedNotes();
        
        this.sessionKey = null;
        this.decryptedNotes.clear();
        this.sessionActive = false;
        this.currentNoteId = null;
        
        this.clearNotesUI();
        
        this.hideLoading();
        this.showScreen('login');
        
        console.log('👻 Session ended - notes are now ghosts');
    }

    async loadDecryptedNotes() {
        const encryptedData = localStorage.getItem('ghost_notes_data');
        if (!encryptedData) {
            console.log('No notes found');
            return;
        }
        
        try {
            const encrypted = JSON.parse(encryptedData);
            const decryptedText = await this.decryptData(encrypted, this.sessionKey);
            const notesData = JSON.parse(decryptedText);
            
            this.decryptedNotes.clear();
            for (const [id, note] of Object.entries(notesData)) {
                this.decryptedNotes.set(id, note);
            }
            
            console.log(`📝 Loaded ${this.decryptedNotes.size} notes`);
            
        } catch (error) {
            console.error('Failed to load notes:', error);
        }
    }

    async saveEncryptedNotes() {
        try {
            const notesData = {};
            for (const [id, note] of this.decryptedNotes) {
                notesData[id] = note;
            }
            
            const notesJson = JSON.stringify(notesData);
            const encrypted = await this.encryptData(notesJson, this.sessionKey);
            
            localStorage.setItem('ghost_notes_data', JSON.stringify(encrypted));
            
            console.log(`💾 Saved ${this.decryptedNotes.size} encrypted notes`);
            
        } catch (error) {
            console.error('Failed to save notes:', error);
        }
    }

    async encryptData(text, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
        
        return {
            encrypted: Array.from(new Uint8Array(encrypted)),
            iv: Array.from(iv)
        };
    }

    async decryptData(encryptedData, key) {
        const encrypted = new Uint8Array(encryptedData.encrypted);
        const iv = new Uint8Array(encryptedData.iv);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    async createWelcomeNote() {
        const note = {
            id: crypto.randomUUID(),
            title: '👻 Welcome to Ghost Notes',
            content: `Welcome to Ghost Notes! 

Your notes are now protected by advanced cryptography. Here's what makes them special:

🔐 **Encrypted Storage**: Your notes are encrypted when the app closes
👻 **Ghost Mode**: Notes vanish from memory when you're away  
📱 **Auto-Lock**: Automatic protection after inactivity
🔒 **Limited Attempts**: Protection against brute force attacks

**Important:**
- Remember your PIN - there's no password recovery
- Your notes are completely private and secure
- Close the app to make your notes disappear

Start writing your secret thoughts! They'll be safe as ghosts when you leave.`,
            tags: ['welcome', 'info'],
            created: Date.now(),
            modified: Date.now()
        };
        
        this.decryptedNotes.set(note.id, note);
    }

    createNewNote() {
        const note = {
            id: crypto.randomUUID(),
            title: 'New Note',
            content: '',
            tags: [],
            created: Date.now(),
            modified: Date.now()
        };
        
        this.decryptedNotes.set(note.id, note);
        this.selectNote(note.id);
        this.updateNotesListUI();
        
        setTimeout(() => {
            document.getElementById('note-title').focus();
            document.getElementById('note-title').select();
        }, 100);
    }

    selectNote(noteId) {
        this.currentNoteId = noteId;
        const note = this.decryptedNotes.get(noteId);
        
        if (note) {
            document.getElementById('note-title').value = note.title;
            document.getElementById('note-content').value = note.content;
            document.getElementById('note-created').textContent = `Created: ${new Date(note.created).toLocaleString()}`;
            document.getElementById('note-modified').textContent = `Modified: ${new Date(note.modified).toLocaleString()}`;
            
            document.getElementById('welcome-message').style.display = 'none';
            document.getElementById('note-editor').style.display = 'flex';
            
            this.updateNotesListUI();
        }
    }

    async saveCurrentNote() {
        if (!this.currentNoteId) return;
        
        const note = this.decryptedNotes.get(this.currentNoteId);
        if (!note) return;
        
        note.title = document.getElementById('note-title').value || 'Untitled';
        note.content = document.getElementById('note-content').value;
        note.modified = Date.now();
        
        document.getElementById('note-modified').textContent = `Modified: ${new Date(note.modified).toLocaleString()}`;
        this.updateNotesListUI();
        
        await this.saveEncryptedNotes();
        
        this.showTemporaryMessage('Note saved');
    }

    autoSaveNote() {
        clearTimeout(this.autoSaveTimer);
        this.autoSaveTimer = setTimeout(() => {
            this.saveCurrentNote();
        }, 2000);
    }

    async deleteCurrentNote() {
        if (!this.currentNoteId) return;
        
        if (confirm('Are you sure you want to delete this note?')) {
            this.decryptedNotes.delete(this.currentNoteId);
            this.currentNoteId = null;
            
            document.getElementById('note-editor').style.display = 'none';
            document.getElementById('welcome-message').style.display = 'flex';
            
            this.updateNotesListUI();
            await this.saveEncryptedNotes();
            
            this.showTemporaryMessage('Note deleted');
        }
    }

    updateNotesListUI() {
        const notesList = document.getElementById('notes-list');
        notesList.innerHTML = '';
        
        if (this.decryptedNotes.size === 0) {
            notesList.innerHTML = '<div style="padding: 1rem; text-align: center; color: var(--text-muted);">No notes yet. Create your first note!</div>';
            return;
        }
        
        const sortedNotes = Array.from(this.decryptedNotes.values())
            .sort((a, b) => b.modified - a.modified);
        
        sortedNotes.forEach(note => {
            const noteElement = document.createElement('div');
            noteElement.className = 'note-item';
            if (note.id === this.currentNoteId) {
                noteElement.classList.add('active');
            }
            
            noteElement.innerHTML = `
                <div class="note-item-title">${note.title}</div>
                <div class="note-item-preview">${note.content.substring(0, 50)}${note.content.length > 50 ? '...' : ''}</div>
                <div class="note-item-date">${new Date(note.modified).toLocaleDateString()}</div>
            `;
            
            noteElement.addEventListener('click', () => this.selectNote(note.id));
            notesList.appendChild(noteElement);
        });
    }

    clearNotesUI() {
        document.getElementById('notes-list').innerHTML = '';
        document.getElementById('note-title').value = '';
        document.getElementById('note-content').value = '';
        document.getElementById('note-created').textContent = 'Created: --';
        document.getElementById('note-modified').textContent = 'Modified: --';
        
        document.getElementById('note-editor').style.display = 'none';
        document.getElementById('welcome-message').style.display = 'flex';
    }

    resetActivityTimer() {
        clearTimeout(this.autoLockTimer);
        clearTimeout(this.sessionWarningTimer);
        
        if (!this.sessionActive) return;
        
        // Schedule warning before auto-lock
        const warningTime = this.settings.autoLockTimeout - this.settings.sessionWarningTime;
        this.sessionWarningTimer = setTimeout(() => {
            this.showSessionWarning();
        }, warningTime);
        
        // Schedule auto-lock
        this.autoLockTimer = setTimeout(() => {
            this.endSession();
        }, this.settings.autoLockTimeout);
        
        this.updateSessionTimer();
    }

    scheduleAutoLock(delay) {
        clearTimeout(this.autoLockTimer);
        this.autoLockTimer = setTimeout(() => {
            this.endSession();
        }, delay);
    }

    cancelAutoLock() {
        clearTimeout(this.autoLockTimer);
        clearTimeout(this.sessionWarningTimer);
    }

    showSessionWarning() {
        document.getElementById('session-warning').classList.add('active');
        
        let countdown = 30;
        const countdownElement = document.getElementById('warning-countdown');
        
        const countdownTimer = setInterval(() => {
            countdown--;
            countdownElement.textContent = countdown;
            
            if (countdown <= 0) {
                clearInterval(countdownTimer);
                this.hideSessionWarning();
                this.endSession();
            }
        }, 1000);
        
        // Store timer for cleanup
        this.countdownTimer = countdownTimer;
    }

    hideSessionWarning() {
        document.getElementById('session-warning').classList.remove('active');
        if (this.countdownTimer) {
            clearInterval(this.countdownTimer);
        }
    }

    extendSession() {
        this.hideSessionWarning();
        this.resetActivityTimer();
    }

    cancelSessionWarning() {
        clearTimeout(this.sessionWarningTimer);
        this.hideSessionWarning();
    }

    updateSessionTimer() {
        if (!this.sessionActive) return;
        
        const timerElement = document.getElementById('lock-timer');
        const timeLeft = this.settings.autoLockTimeout;
        const minutes = Math.floor(timeLeft / 60000);
        const seconds = Math.floor((timeLeft % 60000) / 1000);
        
        timerElement.textContent = `Auto-lock in ${minutes}:${seconds.toString().padStart(2, '0')}`;
    }

    updateAttemptsDisplay() {
        const remaining = this.settings.maxGuesses - this.settings.currentGuesses;
        document.getElementById('attempts-remaining').textContent = `${remaining} attempts remaining`;
    }

    showLoading(message) {
        const overlay = document.getElementById('loading-overlay');
        const text = overlay.querySelector('.loading-text');
        text.textContent = message;
        overlay.classList.add('active');
    }

    hideLoading() {
        document.getElementById('loading-overlay').classList.remove('active');
    }

    showError(message) {
        document.getElementById('error-message').textContent = message;
        setTimeout(() => {
            document.getElementById('error-message').textContent = '';
        }, 5000);
    }

    showTemporaryMessage(message) {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--accent-success);
            color: white;
            padding: 0.8rem 1.2rem;
            border-radius: 8px;
            z-index: 3000;
            animation: slideIn 0.3s ease;
        `;
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 2000);
    }

    setupPWA() {
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            this.deferredPrompt = e;
        });
        
        if (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) {
            console.log('📱 Running as PWA');
        }
    }
}

// Initialize the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.ghostNotes = new GhostNotesApp();
});

// Add toast animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
`;
document.head.appendChild(style); 