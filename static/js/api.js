
const API_BASE = '/api';

const api = {
  currentUser() {
    try {
      return JSON.parse(localStorage.getItem('evidence_user'));
    } catch {
      return null;
    }
  },

  getToken() {
    return localStorage.getItem('evidence_token');
  },


async request(endpoint, options = {}) {
  const headers = { ...(options.headers || {}) };

  const isFormData = options.body instanceof FormData;

  // Let the browser set the multipart boundary automatically.
  if (!isFormData) {
    headers['Content-Type'] = 'application/json';
  }

  const token = this.getToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return {
        ok: false,
        error: data.error || data.message || 'Request failed',
        data,
        status: response.status
      };
    }

    return { ok: true, data };

  } catch {
    return {
      ok: false,
      error: 'Unable to connect to the server.'
    };
  }
},


  async register(username, email, password) {
    const result = await this.request('/users', {
      method: 'POST',
      body: JSON.stringify({ username, email, password })
    });

    if (!result.ok) return result;

    return this.login(email, password);
  },

  async login(email, password) {
    const result = await this.request('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });

    if (!result.ok) return result;

    localStorage.setItem(
      'evidence_token',
      result.data.access_token
    );

    localStorage.setItem(
      'evidence_user',
      JSON.stringify(result.data.user)
    );

    return {
      ok: true,
      user: result.data.user
    };
  },

  logout() {
    localStorage.removeItem('evidence_token');
    localStorage.removeItem('evidence_user');
    location.href = '/';
  },

  async registerPublicKey(publicKey) {
    const user = this.currentUser();

    if (!user) {
      return { ok: false, error: 'Please sign in first.' };
    }

    return this.request(`/users/${user.id}/keys`, {
      method: 'POST',
      body: JSON.stringify({
        public_key: publicKey,
        algorithm: 'ECDSA-P256'
      })
    });
  },

  async listUsers() {
    const result = await this.request('/users');

    if (!result.ok) return result;

    return {
      ok: true,
      users: result.data.users
    };
  },

  async getUserKeys() {
    const user = this.currentUser();

    if (!user) {
      return { ok: false, error: 'Please sign in first.' };
    }

    return this.request(`/users/${user.id}/keys`);
  },

  async getEncryptedKeyBackup(keyId) {
    const user = this.currentUser();
    if (!user || !keyId) return { ok: false, error: 'Account or public-key ID is missing.' };
    return this.request(`/users/${user.id}/keys/${keyId}/backup`);
  },

  async saveEncryptedKeyBackup(keyId, backup) {
    const user = this.currentUser();
    if (!user || !keyId) return { ok: false, error: 'Account or public-key ID is missing.' };
    return this.request(`/users/${user.id}/keys/${keyId}/backup`, {
      method: 'PUT',
      body: JSON.stringify(backup)
    });
  },


async sendMessage(messageData) {
  if (messageData instanceof FormData) {
    return this.request('/messages', {
      method: 'POST',
      body: messageData
    });
  }

  return this.request('/messages', {
    method: 'POST',
    body: JSON.stringify(messageData)
  });
},


  async getInbox() {
    return this.request('/messages/inbox');
  },

  async downloadAttachment(url, filename) {
  try {
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.getToken()}`
      }
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      return {
        ok: false,
        error: data.error || 'Download failed'
      };
    }

    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(objectUrl);

    return { ok: true };

  } catch {
    return {
      ok: false,
      error: 'Unable to download attachment.'
    };
  }
},

  async getSentMessages() {
    return this.request('/messages/sent');
  },

  async verify(messageId) {
    return this.request(`/messages/${messageId}/verify`, {
      method: 'POST'
    });
  },

  async getLedger() {
    return this.request('/ledger');
  },

  async checkLedger() {
    return this.request('/ledger/verify');
  },

    async getAlerts() {
    return this.request('/alerts');
  },
  async getDemoAttacks() {
    return this.request('/demo/attacks');
  },

  async prepareInteractiveTampering() {
    return this.request('/demo/message-tampering/prepare', { method: 'POST' });
  },

  async tamperInteractiveMessage(sessionId, modifiedMessage) {
    return this.request(`/demo/message-tampering/${encodeURIComponent(sessionId)}/tamper`, {
      method: 'POST',
      body: JSON.stringify({ modified_message: modifiedMessage })
    });
  },

  async runInteractiveTamperingCheck(sessionId, check) {
    return this.request(`/demo/message-tampering/${encodeURIComponent(sessionId)}/check`, {
      method: 'POST',
      body: JSON.stringify({ check })
    });
  },

  async completeInteractiveTampering(sessionId) {
    return this.request(`/demo/message-tampering/${encodeURIComponent(sessionId)}/complete`, {
      method: 'POST'
    });
  },

  async prepareInteractiveForgery() {
    return this.request('/demo/forged-signature/prepare', { method: 'POST' });
  },

  async createInteractiveForgery(sessionId) {
    return this.request(`/demo/forged-signature/${encodeURIComponent(sessionId)}/create`, {
      method: 'POST'
    });
  },

  async submitInteractiveForgery(sessionId) {
    return this.request(`/demo/forged-signature/${encodeURIComponent(sessionId)}/submit`, {
      method: 'POST'
    });
  },

  async verifyInteractiveForgery(sessionId) {
    return this.request(`/demo/forged-signature/${encodeURIComponent(sessionId)}/verify`, {
      method: 'POST'
    });
  },

  async completeInteractiveForgery(sessionId) {
    return this.request(`/demo/forged-signature/${encodeURIComponent(sessionId)}/complete`, {
      method: 'POST'
    });
  },

  async prepareInteractiveReplay() {
    return this.request('/demo/replay/prepare', { method: 'POST' });
  },
  async acceptInteractiveReplay(sessionId) {
    return this.request(`/demo/replay/${encodeURIComponent(sessionId)}/accept`, { method: 'POST' });
  },
  async submitInteractiveReplay(sessionId) {
    return this.request(`/demo/replay/${encodeURIComponent(sessionId)}/submit`, { method: 'POST' });
  },
  async verifyInteractiveReplay(sessionId) {
    return this.request(`/demo/replay/${encodeURIComponent(sessionId)}/verify`, { method: 'POST' });
  },
  async completeInteractiveReplay(sessionId) {
    return this.request(`/demo/replay/${encodeURIComponent(sessionId)}/complete`, { method: 'POST' });
  },

  async prepareInteractiveExpiredSignature() {
    return this.request('/demo/expired-signature/prepare', { method: 'POST' });
  },
  async submitInteractiveExpiredSignature(sessionId) {
    return this.request(`/demo/expired-signature/${encodeURIComponent(sessionId)}/submit`, { method: 'POST' });
  },
  async verifyInteractiveExpiredSignature(sessionId) {
    return this.request(`/demo/expired-signature/${encodeURIComponent(sessionId)}/verify`, { method: 'POST' });
  },
  async completeInteractiveExpiredSignature(sessionId) {
    return this.request(`/demo/expired-signature/${encodeURIComponent(sessionId)}/complete`, { method: 'POST' });
  },

  async prepareInteractiveRevokedKey() {
    return this.request('/demo/revoked-key/prepare', { method: 'POST' });
  },
  async revokeInteractiveDemoKey(sessionId) {
    return this.request(`/demo/revoked-key/${encodeURIComponent(sessionId)}/revoke`, { method: 'POST' });
  },
  async submitInteractiveRevokedPacket(sessionId) {
    return this.request(`/demo/revoked-key/${encodeURIComponent(sessionId)}/submit`, { method: 'POST' });
  },
  async verifyInteractiveRevokedPacket(sessionId) {
    return this.request(`/demo/revoked-key/${encodeURIComponent(sessionId)}/verify`, { method: 'POST' });
  },
  async completeInteractiveRevokedKey(sessionId) {
    return this.request(`/demo/revoked-key/${encodeURIComponent(sessionId)}/complete`, { method: 'POST' });
  },

  async prepareInteractiveLedgerTampering() {
    return this.request('/demo/ledger-tampering/prepare', { method: 'POST' });
  },
  async tamperInteractiveLedgerRecord(sessionId, modifiedDetails) {
    return this.request(`/demo/ledger-tampering/${encodeURIComponent(sessionId)}/tamper`, {
      method: 'POST', body: JSON.stringify({ modified_details: modifiedDetails })
    });
  },
  async verifyInteractiveLedgerChain(sessionId) {
    return this.request(`/demo/ledger-tampering/${encodeURIComponent(sessionId)}/verify`, { method: 'POST' });
  },
  async completeInteractiveLedgerTampering(sessionId) {
    return this.request(`/demo/ledger-tampering/${encodeURIComponent(sessionId)}/complete`, { method: 'POST' });
  },

  async runDemoAttack(attackType) {
  return this.request(`/demo/attacks/${encodeURIComponent(attackType)}`, {
    method: 'POST'
  });
},

async runLedgerTamperingDemo() {
  return this.request('/demo/ledger-tampering', {
    method: 'POST'
  });
},
};
