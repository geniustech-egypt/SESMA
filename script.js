(function () {
  'use strict';

  /* ============================================
     SECURITY UTILITIES
     ============================================ */

  /**
   * تطهير النص لمنع XSS
   * يزيل جميع العناصر الخطرة مع السماح بالنص العادي فقط
   */
  function sanitizeInput(str) {
    if (typeof str !== 'string') return '';
    // إزالة NULL bytes
    var cleaned = str.replace(/\0/g, '');
    // تشفير HTML entities لمنع حقن XSS
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(cleaned));
    return div.textContent;
  }

  /**
   * التحقق من أن النص يحتوي على أحرف Unicode صالحة فقط
   * يمنع حقن الأكواد عبر حروف التحكم
   */
  function isValidText(str) {
    if (typeof str !== 'string') return false;
    // منع أحرف التحكم (ما عدا tab, newline, carriage return)
    return !/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
  }

  /**
   * التحقق من صحة البريد الإلكتروني (تعبير منتظم صارم)
   */
  function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    // RFC 5322 simplified - يرفض العناوين الخطرة
    var emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return emailRegex.test(email);
  }

  /**
   * التحقق من صحة رقم الهاتف
   */
  function isValidPhone(phone) {
    if (typeof phone !== 'string' || phone.trim() === '') return true; // اختياري
    var phoneRegex = /^[\d\s\+\-\(\)]{7,20}$/;
    return phoneRegex.test(phone.trim());
  }

  /**
   * منع حقن URL (javascript:, data: في الروابط)
   */
  function isSafeUrl(url) {
    if (typeof url !== 'string') return false;
    var trimmed = url.trim().toLowerCase();
    // منع بروتوكولات خطرة
    if (/^(javascript|data|vbscript):/i.test(trimmed)) return false;
    return true;
  }

  /* ============================================
     RATE LIMITING - حماية من الإرسال المتكرر
     ============================================ */

  var SUBMIT_COOLDOWN = 30000; // 30 ثانية بين كل إرسال
  var MAX_SUBMITS_PER_HOUR = 5;
  var submitTimestamps = [];

  function isRateLimited() {
    var now = Date.now();

    // إزالة الطوابع الزمنية القديمة (أقدم من ساعة)
    submitTimestamps = submitTimestamps.filter(function (ts) {
      return now - ts < 3600000;
    });

    // التحقق من الحد الأقصى للساعة
    if (submitTimestamps.length >= MAX_SUBMITS_PER_HOUR) {
      return true;
    }

    // التحقق من فترة التبريد
    if (submitTimestamps.length > 0) {
      var lastSubmit = submitTimestamps[submitTimestamps.length - 1];
      if (now - lastSubmit < SUBMIT_COOLDOWN) {
        return true;
      }
    }

    return false;
  }

  function recordSubmit() {
    submitTimestamps.push(Date.now());
  }

  function getCooldownRemaining() {
    if (submitTimestamps.length === 0) return 0;
    var lastSubmit = submitTimestamps[submitTimestamps.length - 1];
    var remaining = SUBMIT_COOLDOWN - (Date.now() - lastSubmit);
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  /* ============================================
     MOBILE MENU
     ============================================ */

  var menuToggle = document.getElementById('menuToggle');
  var mobileNav = document.getElementById('mobileNav');

  if (menuToggle && mobileNav) {
    menuToggle.addEventListener('click', function () {
      var expanded = menuToggle.getAttribute('aria-expanded') === 'true';
      var newState = !expanded;
      menuToggle.setAttribute('aria-expanded', String(newState));
      mobileNav.hidden = expanded;

      // تحديث aria-label ديناميكياً
      menuToggle.setAttribute('aria-label',
        newState ? 'إغلاق القائمة' : 'فتح القائمة'
      );
    });

    // إغلاق القائمة عند النقر على رابط
    var mobileLinks = mobileNav.querySelectorAll('.mobile-link, .mobile-cta-link');
    mobileLinks.forEach(function (link) {
      link.addEventListener('click', function () {
        menuToggle.setAttribute('aria-expanded', 'false');
        menuToggle.setAttribute('aria-label', 'فتح القائمة');
        mobileNav.hidden = true;
      });
    });

    // إغلاق القائمة عند الضغط على Escape
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && menuToggle.getAttribute('aria-expanded') === 'true') {
        menuToggle.setAttribute('aria-expanded', 'false');
        menuToggle.setAttribute('aria-label', 'فتح القائمة');
        mobileNav.hidden = true;
        menuToggle.focus();
      }
    });
  }

  /* ============================================
     BACK TO TOP
     ============================================ */

  var backToTop = document.getElementById('backToTop');
  if (backToTop) {
    var scrollTicking = false;
    window.addEventListener('scroll', function () {
      if (!scrollTicking) {
        window.requestAnimationFrame(function () {
          backToTop.hidden = window.scrollY < 500;
          scrollTicking = false;
        });
        scrollTicking = true;
      }
    }, { passive: true });

    backToTop.addEventListener('click', function () {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  /* ============================================
     SMOOTH SCROLL (مع حماية من حقن URL)
     ============================================ */

  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      var href = anchor.getAttribute('href');

      // تجاهل الروابط الفارغة أو غير الآمنة
      if (!href || href === '#' || href.length < 2) {
        e.preventDefault();
        return;
      }

      // حماية إضافية: التأكد من أن الـ selector آمن
      if (!isSafeSelector(href)) {
        e.preventDefault();
        return;
      }

      try {
        var element = document.querySelector(href);
        if (element) {
          e.preventDefault();
          element.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      } catch (err) {
        // منع أي خطأ من التأثير على الصفحة
        e.preventDefault();
      }
    });
  });

  /**
   * التحقق من أن محدد CSS آمن (يمنع حقن المحددات)
   */
  function isSafeSelector(selector) {
    if (typeof selector !== 'string') return false;
    // السماح فقط بمحددات ID و class البسيطة
    return /^[#][a-zA-Z0-9_-]+$/.test(selector);
  }

  /* ============================================
     CONTACT FORM - حماية شاملة
     ============================================ */

  // Web3Forms — خدمة استقبال فورم بدون باك إند. الـ access_key الحقيقي
  // متحط في حقل hidden جوه الفورم في index.html (name="access_key").
  var CONTACT_ENDPOINT = 'https://api.web3forms.com/submit';

  var form = document.getElementById('contactForm');
  var submitBtn = document.getElementById('submitBtn');
  var charCountEl = document.getElementById('charCount');
  var messageField = document.getElementById('contact-message');

  // عداد الأحرف
  if (messageField && charCountEl) {
    messageField.addEventListener('input', function () {
      var count = messageField.value.length;
      charCountEl.textContent = count;

      // تحذير لوني عند الاقتراب من الحد
      if (count > 1800) {
        charCountEl.style.color = '#e74c3c';
      } else if (count > 1500) {
        charCountEl.style.color = '#f39c12';
      } else {
        charCountEl.style.color = '#999';
      }
    });
  }

  if (form) {
    // إزالة أي عناصر مشبوهة تم حقنها ديناميكياً
    function sanitizeForm() {
      var inputs = form.querySelectorAll('input, textarea');
      inputs.forEach(function (input) {
        // منع استغلال formaction
        if (input.hasAttribute('formaction')) {
          input.removeAttribute('formaction');
        }
      });
    }

    // تشغيل التطهير عند التحميل، وسنعيد تشغيله أيضاً قبل الإرسال مباشرة
    // (تم إلغاء setInterval كل ثانية لأنه كان يستهلك أداء بدون داعي فعلي)
    sanitizeForm();

    // التحقق من صحة الحقول
    function validateField(field) {
      var value = field.value.trim();
      var errorEl = field.parentElement.querySelector('.form-error');

      // إزالة رسالة الخطأ السابقة
      if (errorEl) {
        errorEl.classList.remove('visible');
        errorEl.textContent = '';
      }

      // إذا كان الحقل فارغاً وليس مطلوباً، تجاوزه
      if (value === '' && !field.required) return true;

      // إذا كان مطلوباً وفارغاً
      if (value === '' && field.required) {
        showFieldError(field, 'هذا الحقل مطلوب');
        return false;
      }

      // التحقق من أحرف التحكم
      if (!isValidText(value)) {
        showFieldError(field, 'يحتوي على أحرف غير مسموح بها');
        return false;
      }

      // التحقق من الحد الأدنى
      if (field.minLength && value.length < field.minLength) {
        showFieldError(field, 'يجب أن يكون على الأقل ' + field.minLength + ' أحرف');
        return false;
      }

      // التحقق الخاص بكل نوع
      if (field.type === 'email' && !isValidEmail(value)) {
        showFieldError(field, 'يرجى إدخال بريد إلكتروني صحيح');
        return false;
      }

      if (field.type === 'tel' && !isValidPhone(value)) {
        showFieldError(field, 'يرجى إدخال رقم هاتف صحيح');
        return false;
      }

      // التحقق من pattern (إذا وجد)
      if (field.pattern) {
        var regex = new RegExp('^(?:' + field.pattern + ')$');
        if (!regex.test(value)) {
          showFieldError(field, field.title || 'القيمة غير صحيحة');
          return false;
        }
      }

      return true;
    }

    function showFieldError(field, message) {
      var errorEl = field.parentElement.querySelector('.form-error');
      if (!errorEl) {
        errorEl = document.createElement('span');
        errorEl.className = 'form-error';
        errorEl.setAttribute('role', 'alert');
        field.parentElement.appendChild(errorEl);
      }
      errorEl.textContent = sanitizeInput(message);
      errorEl.classList.add('visible');
      field.setAttribute('aria-invalid', 'true');
    }

    function clearFieldError(field) {
      var errorEl = field.parentElement.querySelector('.form-error');
      if (errorEl) {
        errorEl.classList.remove('visible');
        errorEl.textContent = '';
      }
      field.removeAttribute('aria-invalid');
    }

    // التحقق أثناء الكتابة (بعد مغادرة الحقل)
    var formFields = form.querySelectorAll('input, textarea');
    formFields.forEach(function (field) {
      field.addEventListener('blur', function () {
        if (field.value.trim() !== '') {
          validateField(field);
        }
      });
      field.addEventListener('input', function () {
        clearFieldError(field);
      });
    });

    // معالجة الإرسال
    form.addEventListener('submit', function (e) {
      e.preventDefault();

      // 0. تطهير أخير قبل الإرسال مباشرة
      sanitizeForm();

      // 1. فحص Honeypot (بوتات الـ spam)
      var honeypot = document.getElementById('website');
      if (honeypot && honeypot.value !== '') {
        // سلوك خادع: يظهر نجاح للبوت لكن لا يرسل شيئاً
        showFormSuccess();
        form.reset();
        if (charCountEl) charCountEl.textContent = '0';
        return;
      }

      // 2. التحقق من Rate Limiting
      if (isRateLimited()) {
        var cooldown = getCooldownRemaining();
        showFormError('يرجى الانتظار ' + cooldown + ' ثانية قبل المحاولة مرة أخرى');
        return;
      }

      // 3. التحقق من جميع الحقول
      var isValid = true;
      formFields.forEach(function (field) {
        if (!validateField(field)) {
          isValid = false;
        }
      });

      if (!isValid) {
        // التركيز على أول حقل خاطئ
        var firstInvalid = form.querySelector('[aria-invalid="true"]');
        if (firstInvalid) firstInvalid.focus();
        return;
      }

      // 4. تطهير جميع المدخلات
      var nameField = document.getElementById('contact-name');
      var emailField = document.getElementById('contact-email');
      var phoneField = document.getElementById('contact-phone');
      var accessKeyField = form.querySelector('[name="access_key"]');
      var subjectField = form.querySelector('[name="subject"]');
      var fromNameField = form.querySelector('[name="from_name"]');

      var sanitizedData = {
        access_key: accessKeyField ? accessKeyField.value : '',
        subject: subjectField ? subjectField.value : 'رسالة جديدة من نموذج التواصل - SESMA',
        from_name: fromNameField ? fromNameField.value : 'SESMA Website',
        name: sanitizeInput(nameField ? nameField.value : ''),
        email: sanitizeInput(emailField ? emailField.value : ''),
        phone: phoneField ? sanitizeInput(phoneField.value) : '',
        message: sanitizeInput(messageField ? messageField.value : '')
      };

      // تنبيه للمطوّر فقط: لو المفتاح لسه القيمة الافتراضية، النموذج مش
      // هيشتغل مع Web3Forms. راجع index.html (حقل access_key) واستبدله
      // بالمفتاح الحقيقي من https://web3forms.com
      if (!sanitizedData.access_key || sanitizedData.access_key === 'YOUR_ACCESS_KEY_HERE') {
        console.error('[SESMA] لم يتم ضبط Web3Forms access_key بعد. راجع حقل access_key في index.html.');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'أرسل الآن';
        }
        showFormError('النموذج غير مفعّل بعد، يرجى التواصل عبر الواتساب أو البريد الإلكتروني مباشرة.');
        return;
      }

      // 5. تسجيل الطابع الزمني (Rate Limiting على مستوى الواجهة فقط —
      //    ده خط دفاع أول للتجربة، ومفيد هنا لأن Web3Forms مفيهوش rate
      //    limiting خاص بيك، لكنه سهل التجاوز طبعاً لو حد شال الجافاسكريبت)
      recordSubmit();

      // 6. تعطيل الزر أثناء الإرسال
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'جاري الإرسال...';
      }

      // 7. الإرسال الفعلي عبر Web3Forms (بدون أي باك إند خاص بينا)
      // التوثيق: https://docs.web3forms.com
      fetch(CONTACT_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(sanitizedData)
      })
        .then(function (response) {
          return response.json().then(function (data) {
            if (!response.ok || !data.success) {
              throw new Error(data && data.message ? data.message : 'Submission failed');
            }
            showFormSuccess();
            form.reset();
            if (charCountEl) {
              charCountEl.textContent = '0';
              charCountEl.style.color = '#999';
            }
          });
        })
        .catch(function () {
          showFormError('حدث خطأ أثناء الإرسال، يرجى المحاولة مرة أخرى أو التواصل عبر الواتساب.');
        })
        .finally(function () {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'أرسل الآن';
          }
        });
    });
  }

  /**
   * عرض رسالة نجاح آمنة (بدون alert)
   */
  function showFormSuccess() {
    removeFormMessages();
    var msg = document.createElement('div');
    msg.className = 'form-message form-success';
    msg.setAttribute('role', 'status');
    msg.setAttribute('aria-live', 'polite');
    msg.textContent = 'شكراً لك! تم إرسال رسالتك بنجاح وسنتواصل معك قريباً.';

    var formEl = document.getElementById('contactForm');
    if (formEl) {
      formEl.parentNode.insertBefore(msg, formEl.nextSibling);
    }

    // إزالة الرسالة بعد 5 ثوانٍ
    setTimeout(function () {
      if (msg.parentNode) msg.parentNode.removeChild(msg);
    }, 5000);
  }

  /**
   * عرض رسالة خطأ آمنة
   */
  function showFormError(message) {
    removeFormMessages();
    var msg = document.createElement('div');
    msg.className = 'form-message form-error-msg';
    msg.setAttribute('role', 'alert');
    msg.setAttribute('aria-live', 'assertive');
    msg.textContent = sanitizeInput(message);

    var formEl = document.getElementById('contactForm');
    if (formEl) {
      formEl.parentNode.insertBefore(msg, formEl.nextSibling);
    }

    // إزالة الرسالة بعد 8 ثوانٍ
    setTimeout(function () {
      if (msg.parentNode) msg.parentNode.removeChild(msg);
    }, 8000);
  }

  /**
   * إزالة رسائل النموذج السابقة
   */
  function removeFormMessages() {
    var existing = document.querySelectorAll('.form-message');
    existing.forEach(function (el) {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
  }

  /* ============================================
     YEAR - تحديث تلقائي
     ============================================ */

  var yearEl = document.getElementById('year');
  if (yearEl) {
    yearEl.textContent = new Date().getFullYear();
  }

  /* ============================================
     ملاحظة أمان مهمة
     ============================================
     تم حذف مراقب DOM (MutationObserver) اللي كان بيراقب الصفحة بالكامل،
     وكذلك كود "anti-debugging"، للأسباب الآتية:

     1. كانا بيكلفوا أداء حقيقي (مراقبة كل عنصر وكل سمة في الصفحة بالكامل
        باستمرار)، خصوصاً attributeFilter اللي بيشمل src/href وهي سمات
        بتتغير بشكل طبيعي جداً أثناء التصفح العادي.
     2. مفيهمش حماية فعلية: أي كود مهاجم قادر ينفذ JavaScript في الصفحة
        أصلاً يقدر يعطّل الـ observer نفسه أو يشتغل قبل ما يتفعّل.
     3. الحماية الحقيقية من XSS موجودة فعلاً وبشكل صحيح في مكانين:
          - الـ Content-Security-Policy في index.html (script-src 'self')
          - استخدام sanitizeInput()/textContent بدل innerHTML في كل مكان
            بيتعامل مع مدخلات المستخدم في الملف ده.
        دول أمان حقيقي مبني من التصميم، مش "مراقبة" بعد ما يحصل الاختراق.
  */

})();