
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
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };

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

  async sendMessage(messageData) {
    return this.request('/messages', {
      method: 'POST',
      body: JSON.stringify(messageData)
    });
  },

  async getInbox() {
    return this.request('/messages/inbox');
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
