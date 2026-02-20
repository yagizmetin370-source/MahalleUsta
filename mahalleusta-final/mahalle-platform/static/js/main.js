/* ── MahalleUsta – Main JS ─────────────────────────────── */

// Navbar scroll
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => {
  if (navbar) navbar.classList.toggle('scrolled', window.scrollY > 10);
}, { passive: true });

// Mobile nav
const navToggle = document.getElementById('navToggle');
const navMenu   = document.getElementById('navMenu');
if (navToggle && navMenu) {
  navToggle.addEventListener('click', () => {
    const open = navMenu.classList.toggle('open');
    navToggle.classList.toggle('open', open);
    document.body.style.overflow = open ? 'hidden' : '';
  });
  document.addEventListener('click', e => {
    if (navMenu.classList.contains('open') && !navToggle.contains(e.target) && !navMenu.contains(e.target)) {
      navMenu.classList.remove('open');
      navToggle.classList.remove('open');
      document.body.style.overflow = '';
    }
  });
}

// Toast auto dismiss
document.querySelectorAll('.toast').forEach(toast => {
  setTimeout(() => {
    toast.style.transition = 'opacity 0.4s, transform 0.4s';
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(110%)';
    setTimeout(() => toast.remove(), 400);
  }, 5000);
});

// Cascading location selects
const citySelect  = document.getElementById('city');
const distSelect  = document.getElementById('district');
const neighSelect = document.getElementById('neighborhood');

async function loadDistricts(city, selectedDist) {
  if (!distSelect || !city) return;
  try {
    const res = await fetch(`/api/districts?city=${encodeURIComponent(city)}`);
    const data = await res.json();
    distSelect.innerHTML = '<option value="">İlçe Seçin</option>';
    data.forEach(d => {
      const opt = new Option(d, d, d === selectedDist, d === selectedDist);
      distSelect.add(opt);
    });
    if (neighSelect) neighSelect.innerHTML = '<option value="">Mahalle Seçin</option>';
  } catch(e) { console.error('Districts fetch failed', e); }
}

async function loadNeighborhoods(city, dist, selectedNeigh) {
  if (!neighSelect || !city || !dist) return;
  try {
    const res = await fetch(`/api/neighborhoods?city=${encodeURIComponent(city)}&district=${encodeURIComponent(dist)}`);
    const data = await res.json();
    neighSelect.innerHTML = '<option value="">Mahalle Seçin</option>';
    data.forEach(n => {
      const opt = new Option(n, n, n === selectedNeigh, n === selectedNeigh);
      neighSelect.add(opt);
    });
  } catch(e) { console.error('Neighborhoods fetch failed', e); }
}

if (citySelect) {
  citySelect.addEventListener('change', () => loadDistricts(citySelect.value, ''));
}
if (distSelect) {
  distSelect.addEventListener('change', () => {
    if (citySelect) loadNeighborhoods(citySelect.value, distSelect.value, '');
  });
}

// Hero search
const heroForm  = document.getElementById('heroSearchForm');
const heroInput = document.getElementById('heroSearchInput');
if (heroForm) {
  heroForm.addEventListener('submit', e => {
    e.preventDefault();
    const q = heroInput.value.trim();
    window.location.href = q ? `/search?q=${encodeURIComponent(q)}` : '/search';
  });
}

// Image preview
const photoInput   = document.getElementById('photo');
const photoPreview = document.getElementById('photoPreview');
if (photoInput && photoPreview) {
  photoInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      photoPreview.src = ev.target.result;
      photoPreview.style.display = 'block';
    };
    reader.readAsDataURL(file);
  });
}

// Form submit – loading state
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', function() {
    const btn = this.querySelector('[type="submit"]');
    if (!btn || btn._loading) return;
    btn._loading = true;
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> İşleniyor...';
    btn.style.opacity = '0.75';
    btn.disabled = true;
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.style.opacity = '';
      btn.disabled = false;
      btn._loading = false;
    }, 10000);
  });
});

// Counter animation
function animateCounter(el, target) {
  let cur = 0;
  const dur = 1200;
  const step = target / (dur / 16);
  const timer = setInterval(() => {
    cur = Math.min(cur + step, target);
    el.textContent = Math.floor(cur).toLocaleString('tr-TR');
    if (cur >= target) clearInterval(timer);
  }, 16);
}

// Intersection Observer for animations
const io = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    const el = entry.target;

    // Animate counters
    if (el.hasAttribute('data-count')) {
      animateCounter(el, parseInt(el.dataset.count));
    }

    // Reveal anim-up elements
    el.classList.add('visible');

    io.unobserve(el);
  });
}, { threshold: 0.12, rootMargin: '0px 0px -30px 0px' });

document.querySelectorAll('[data-count], .anim-up').forEach(el => io.observe(el));

// Stagger animation for grids
function staggerChildren(selector) {
  document.querySelectorAll(selector).forEach((el, i) => {
    el.style.transitionDelay = `${i * 0.06}s`;
  });
}
staggerChildren('.providers-grid .provider-card');
staggerChildren('.category-grid .category-card');
