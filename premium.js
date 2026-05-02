/* ════════════════════════════════════════════════
   DevSpire — Cyber Terminal Premium JS
   ════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ── Progress bar ───────────────────────────── */
  var bar = document.createElement('div');
  bar.id = 'px-ds-bar';
  document.body.prepend(bar);

  window.addEventListener('scroll', function () {
    var total = document.body.scrollHeight - window.innerHeight;
    bar.style.width = (total > 0 ? (window.scrollY / total) * 100 : 0) + '%';
    /* Navbar glass on scroll */
    var nav = document.querySelector('nav');
    if (nav) nav.classList.toggle('scrolled', window.scrollY > 50);
  }, { passive: true });

  /* ── Stagger observer ───────────────────────── */
  function stagger(sel) {
    var el = document.querySelector(sel);
    if (!el) return;
    el.classList.add('px-stagger');
    new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('px-visible'); }
      });
    }, { threshold: 0.06 }).observe(el);
  }
  stagger('.services-grid');

  /* ── Typing effect on terminal prompt lines ─── */
  function typeEl(el, text, speed) {
    el.textContent = '';
    var i = 0;
    var t = setInterval(function () {
      el.textContent += text[i++];
      if (i >= text.length) clearInterval(t);
    }, speed || 38);
  }

  /* Trigger typing when terminal card enters viewport */
  var typed = false;
  new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting || typed) return;
      typed = true;
      e.currentTarget.disconnect();
      /* Find prompt-line elements inside terminal cards */
      document.querySelectorAll('.terminal-card code, .terminal-card .prompt, .terminal-card pre').forEach(function (code, i) {
        var orig = code.textContent;
        setTimeout(function () { typeEl(code, orig, 22); }, i * 320);
      });
    });
  }, { threshold: 0.3 }).observe(document.querySelector('.terminal-card') || document.body);

  /* ── Generic fade-up for remaining sections ─── */
  var fadeEls = document.querySelectorAll('[class*="section"]:not(#hero), .features-grid, .cta-section');
  fadeEls.forEach(function (el) {
    if (el.style.opacity !== '') return; /* skip if already animated */
    el.style.opacity = '0';
    el.style.transform = 'translateY(28px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.style.opacity = '1';
          e.target.style.transform = 'none';
        }
      });
    }, { threshold: 0.08 }).observe(el);
  });

})();
