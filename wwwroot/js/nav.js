// Reusable Navigation, Auth Guard & Utilities
const API_BASE = '/api';

// Format Rupiah
const formatRp = (num) => 'Rp ' + Number(num || 0).toLocaleString('id-ID');

// XSS Sanitizer
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Current User State
let currentUser = null;
let currentToken = null;
let rolePermissions = [];

function checkAuthGuard(currentPageKey) {
  const token = localStorage.getItem('pos_token');
  const userJson = localStorage.getItem('pos_user');

  if (!token || !userJson) {
    if (!window.location.pathname.endsWith('/login.html')) {
      window.location.href = '/login.html';
      return false;
    }
    return true;
  }

  try {
    currentUser = JSON.parse(userJson);
    currentToken = token;
  } catch (e) {
    localStorage.removeItem('pos_token');
    localStorage.removeItem('pos_user');
    window.location.href = '/login.html';
    return false;
  }

  return true;
}

function getHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-User': currentUser ? currentUser.username : 'Anonymous',
    'X-Role': currentUser ? currentUser.role : 'Kasir',
    'Authorization': currentToken ? `Bearer ${currentToken}` : ''
  };
}

// Toast System
let toastTimeout = null;
function showToast(msg, type = 'info') {
  let toast = document.getElementById('statusToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'statusToast';
    document.body.appendChild(toast);
  }
  clearTimeout(toastTimeout);
  toast.className = 'fixed bottom-4 right-4 z-50 px-3.5 py-2 rounded-md text-xs font-semibold shadow-md ' + 
    (type === 'error' ? 'bg-rose-700 text-white' : type === 'success' ? 'bg-emerald-700 text-white' : 'bg-slate-800 text-white');
  toast.innerText = msg;
  toast.classList.remove('hidden');
  toastTimeout = setTimeout(() => toast.classList.add('hidden'), 2500);
}

// Render Shared Header Nav
async function renderSharedHeader(activePageKey) {
  const headerContainer = document.getElementById('sharedHeader');
  if (!headerContainer) return;

  // Fetch permissions
  try {
    const res = await fetch(`${API_BASE}/roles/permissions`, { headers: getHeaders() });
    rolePermissions = await res.json();
  } catch (e) {}

  const navItems = [
    { key: 'pos', label: 'Kasir', url: '/index.html' },
    { key: 'products', label: 'Produk', url: '/products.html' },
    { key: 'history', label: 'Riwayat', url: '/history.html' },
    { key: 'warehouse', label: 'Gudang', url: '/warehouse.html' },
    { key: 'reports', label: 'Laporan', url: '/reports.html' },
    { key: 'users', label: 'Role & Akses', url: '/users.html' },
    { key: 'logs', label: 'Log Sistem', url: '/logs.html' },
    { key: 'config', label: 'Konfigurasi', url: '/config.html' }
  ];

  // RBAC Filter
  const allowedItems = navItems.filter(item => {
    if (!currentUser || currentUser.role === 'Admin') return true;
    const perm = rolePermissions.find(p => p.role.toLowerCase() === currentUser.role.toLowerCase() && p.tabKey.toLowerCase() === item.key.toLowerCase());
    return perm ? perm.canAccess : false;
  });

  // Check if current page is allowed for this role
  if (currentUser && currentUser.role !== 'Admin') {
    const isAllowed = allowedItems.some(item => item.key === activePageKey);
    if (!isAllowed && allowedItems.length > 0) {
      alert(`Role ${currentUser.role} tidak memiliki hak akses ke halaman ini.`);
      window.location.href = allowedItems[0].url;
      return;
    }
  }

  const roleBadgeColor = currentUser?.role === 'Admin' ? 'bg-emerald-500/20 text-emerald-400' :
                         currentUser?.role === 'Gudang' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400';

  headerContainer.innerHTML = `
    <header class="bg-slate-900 text-white border-b border-slate-800 sticky top-0 z-30">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-2">
        
        <!-- Logo -->
        <a href="/index.html" class="flex items-center space-x-3 shrink-0 hover:opacity-90 transition">
          <span class="font-extrabold tracking-tight text-base text-white">
            KASIR<span class="text-emerald-400">POS</span>
          </span>
          <span class="text-slate-500 text-xs hidden md:inline">|</span>
          <span id="liveClock" class="text-xs text-slate-400 font-mono hidden md:inline"></span>
        </a>

        <!-- Navigation Links -->
        <nav class="flex items-center space-x-1 overflow-x-auto py-1 scrollbar-none" aria-label="Menu Utama">
          ${allowedItems.map(item => `
            <a href="${item.url}" class="px-2.5 py-1.5 rounded-md text-xs font-semibold shrink-0 transition ${item.key === activePageKey ? 'bg-emerald-600 text-white' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
              ${item.label}
            </a>
          `).join('')}
        </nav>

        <!-- User Profile & Logout -->
        <div class="flex items-center space-x-2 shrink-0 text-xs">
          <div class="flex items-center space-x-1.5 px-2 py-1 rounded bg-slate-800 border border-slate-700">
            <span class="font-bold text-slate-200">${escapeHtml(currentUser?.fullName || 'User')}</span>
            <span class="px-1.5 py-0.2 rounded text-[10px] font-extrabold ${roleBadgeColor}">${currentUser?.role || ''}</span>
          </div>
          <button onclick="handleLogout()" class="px-2 py-1 rounded text-[11px] font-bold bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800 transition">
            Keluar
          </button>
        </div>

      </div>
    </header>
  `;

  // Start live clock
  function updateClock() {
    const clockElem = document.getElementById('liveClock');
    if (clockElem) {
      const now = new Date();
      clockElem.innerText = now.toLocaleDateString('id-ID', { weekday: 'short', day: 'numeric', month: 'short' }) + ' ' + now.toLocaleTimeString('id-ID');
    }
  }
  setInterval(updateClock, 1000);
  updateClock();
}

async function handleLogout() {
  if (!confirm('Yakin ingin keluar dari akun ini?')) return;
  try {
    await fetch(`${API_BASE}/auth/logout`, { method: 'POST', headers: getHeaders() });
  } catch (e) {}
  localStorage.removeItem('pos_token');
  localStorage.removeItem('pos_user');
  window.location.href = '/login.html';
}
