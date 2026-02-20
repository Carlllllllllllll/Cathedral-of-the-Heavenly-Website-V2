const GlobalErrorHandler = {
  show: (message) => {
    console.error("[ERROR]", message);
    const el = document.getElementById("error-message");
    if (el) {
      el.textContent = message;
      el.style.color = "#ef4444";
    }
  },
  clear: () => {
    const el = document.getElementById("error-message");
    if (el) {
      el.textContent = "";
    }
  },
};

const translateAuthError = (rawMessage) => {
  const fallback = "حدث خطأ. يرجى المحاولة مرة أخرى.";
  if (!rawMessage || typeof rawMessage !== "string") return fallback;

  const msg = rawMessage.trim();
  if (!msg) return fallback;

  const lower = msg.toLowerCase();

  if (lower.includes("verification code") || lower.includes("6 digits")) {
    return "يرجى إدخال كود التحقق المكون من 6 أرقام";
  }

  if (lower.includes("wrong password") || lower.includes("incorrect password")) {
    return "كلمة المرور غير صحيحة";
  }

  if (lower.includes("user not found") || lower.includes("not found")) {
    return "البيانات غير صحيحة. الرجاء المحاولة مرة أخرى.";
  }

  if (lower.includes("too many") || lower.includes("rate") || lower.includes("limit")) {
    return "تم تنفيذ محاولات كثيرة. يرجى المحاولة لاحقاً.";
  }

  if (lower.includes("invalid") && lower.includes("data")) {
    return "البيانات المدخلة غير صحيحة";
  }

  if (lower.includes("network") || lower.includes("failed to fetch")) {
    return "تعذر الاتصال بالخادم. تحقق من الإنترنت وحاول مرة أخرى.";
  }

  return msg;
};

const whenReady = (callback) => {
  if (typeof callback !== "function") return;
  let fired = false;
  const run = () => {
    if (fired) return;
    fired = true;
    callback();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true });
    window.addEventListener("load", run, { once: true });
    window.addEventListener("pageshow", run, { once: true });
  } else {
    (typeof queueMicrotask === "function"
      ? queueMicrotask
      : (fn) => Promise.resolve().then(fn))(run);
  }
};

whenReady(() => {
  const loginForm = document.getElementById("login-form");
  const errorMessage = document.getElementById("error-message");
  const submitButton = document.querySelector(
    "#login-form button[type='submit']"
  );
  const verificationSection = document.getElementById(
    "verification-code-section"
  );
  const verificationInput = document.getElementById("verification-code");

  if (loginForm) {
    if (verificationInput) {
      verificationInput.addEventListener("input", function () {
        this.value = this.value.replace(/\D/g, "").slice(0, 6);
      });
    }

    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      const verificationCode = verificationInput
        ? verificationInput.value.trim()
        : null;

      errorMessage.textContent = "";
      errorMessage.style.color = "#ef4444";
      if (typeof setButtonLoading === "function") {
        setButtonLoading(submitButton, true, "جاري التحقق...");
      } else {
        submitButton.disabled = true;
        submitButton.innerHTML =
          '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span>' +
          '<span style="margin-right:8px">جاري التحقق...</span>';
      }

      const urlParams = new URLSearchParams(window.location.search);
      const redirect = urlParams.get('redirect');

      try {
        const response = await fetch("/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, verificationCode, redirect }),
        });

        const result = await response.json();

        if (result.requiresVerification) {
          const { value: verificationCode } = await Swal.fire({
            title: "🔑 كود التحقق مطلوب",
            html: `
                            <p style="margin-bottom: 20px; color: #fff; font-size: 14px;">يرجى إدخال كود التحقق المكون من 6 أرقام الذي استلمته من المسؤول</p>
                            <input type="text" id="swal-verification-code" class="swal2-input" 
                                   placeholder="123456" maxlength="6" pattern="[0-9]{6}" 
                                   style="text-align: center; font-size: 24px; letter-spacing: 8px; font-weight: bold; font-family: monospace; color: #ffcc00; border: 2px solid #ffcc00; max-width: 200px; width: 100%; padding: 12px;">
                        `,
            icon: "info",
            iconColor: "#ffcc00",
            showCancelButton: true,
            confirmButtonText: "تأكيد",
            cancelButtonText: "إلغاء",
            confirmButtonColor: "#ffcc00",
            cancelButtonColor: "#666",
            background: "#2a1b3c",
            color: "#fff",
            backdrop: "rgba(0,0,0,0.8)",
            allowOutsideClick: false,
            allowEscapeKey: false,
            customClass: {
              popup: "swal2-popup-responsive",
              container: "swal2-container-responsive",
            },
            didOpen: () => {
              const input = document.getElementById("swal-verification-code");
              if (input) {
                input.focus();
                input.addEventListener("input", function () {
                  this.value = this.value.replace(/\D/g, "").slice(0, 6);
                });
              }
            },
            preConfirm: () => {
              const code = document.getElementById(
                "swal-verification-code"
              ).value;
              if (!code || code.length !== 6) {
                Swal.showValidationMessage("يرجى إدخال 6 أرقام فقط");
                return false;
              }
              return code;
            },
          });

          if (verificationCode) {
            try {
              const verifyResponse = await fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, verificationCode }),
              });

              const verifyResult = await verifyResponse.json();

              if (!verifyResponse.ok || !verifyResult.success) {
                if (
                  verifyResult.message &&
                  (verifyResult.message.includes("Verification code") || verifyResult.message.includes("6 digits"))
                ) {
                  throw new Error("يرجى إدخال 6 أرقام فقط");
                }
                throw new Error(
                  translateAuthError(
                    verifyResult.message || "كود التحقق غير صحيح"
                  )
                );
              }

              window.location.href = verifyResult.redirect || "/form-panel";
            } catch (error) {
              errorMessage.textContent = translateAuthError(error.message);
              errorMessage.style.color = "#ef4444";
            }
          } else {
          }
          return;
        }

        if (!response.ok || !result.success) {
          throw new Error(
            result.message || "البيانات غير صحيحة. الرجاء المحاولة مرة أخرى."
          );
        }

        window.location.href = result.redirect || "/form-panel";
      } catch (error) {
        errorMessage.textContent = translateAuthError(error.message);
        errorMessage.style.color = "#ef4444";
      } finally {
        if (typeof setButtonLoading === "function") {
          setButtonLoading(submitButton, false);
        } else {
          submitButton.disabled = false;
          submitButton.innerHTML = "تسجيل الدخول";
        }
      }
    });
  }
});
