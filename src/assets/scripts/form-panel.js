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
  const createFormButton = document.getElementById("create-form");
  const formModal = document.getElementById("form-modal");
  const closeButton = formModal
    ? formModal.querySelector(".close-button")
    : null;
  const modalCopyLinkBtn = document.getElementById("modal-copy-link");
  const formCreator = document.getElementById("form-creator");
  const questionsContainer = document.getElementById("questions-container");
  const addQuestionButton = document.getElementById("add-question");
  const formsList = document.getElementById("forms-list");
  const targetGradeField = document.getElementById("target-grade");
  const targetGradesHidden = document.getElementById("target-grades");
  const targetGradesToggle = document.getElementById("target-grade-toggle");
  const targetGradesMenu = document.getElementById("target-grade-menu");
  const targetGradesOptions = document.getElementById("target-grade-options");
  const targetGradesChips = document.getElementById("target-grade-chips");
  const targetGradesPlaceholder = document.getElementById("target-grade-placeholder");
  const targetGradesClose = document.getElementById("target-grade-close");
  const logoutButton = document.getElementById("logoutBtn");
  const logoutBtnMobile = document.getElementById("logoutBtnMobile");
  const userRolePill = document.getElementById("user-role-pill");
  const usernameDisplay = document.getElementById("username-display");
  const userMenuName = document.getElementById("user-menu-name");
  const userMenuRole = document.getElementById("user-menu-role");
  const userMenu = document.getElementById("user-menu");

  let questions = [];
  let editingFormLink = null;
  let isHydratingForm = false;

  function refreshQuestionNumbers() {
    document.querySelectorAll(".question").forEach((q, idx) => {
      const numberEl = q.querySelector(".question-number");
      if (numberEl) numberEl.textContent = `سؤال ${idx + 1}`;
    });
  }

  const STORAGE_KEY = "form_modal_data";

  const ALL_GRADE_VALUES = ["all", "prep1", "prep2", "prep3", "sec1", "sec2", "sec3"];
  const GRADE_LABELS = {
    all: "جميع الصفوف",
    prep1: "أولي إعدادي",
    prep2: "ثانية إعدادي",
    prep3: "ثالثة إعدادي",
    sec1: "أولي ثانوي",
    sec2: "ثانية ثانوي",
    sec3: "ثالثة ثانوي",
  };

  function safeJsonParse(raw, fallback) {
    try {
      const parsed = JSON.parse(raw);
      return parsed;
    } catch (e) {
      return fallback;
    }
  }

  function getSelectedTargetGrades() {
    const raw = targetGradesHidden ? targetGradesHidden.value : "";
    const parsed = Array.isArray(safeJsonParse(raw, null)) ? safeJsonParse(raw, []) : [];
    const normalized = parsed
      .map((v) => (v || "").toString().trim().toLowerCase())
      .filter((v) => ALL_GRADE_VALUES.includes(v));
    if (normalized.includes("all") || normalized.length === 0) return ["all"];
    return Array.from(new Set(normalized));
  }

  function setSelectedTargetGrades(values, opts) {
    const closeOnAll = opts && opts.closeOnAll === true;
    let next = Array.isArray(values) ? values : [];
    next = next
      .map((v) => (v || "").toString().trim().toLowerCase())
      .filter((v) => ALL_GRADE_VALUES.includes(v));
    if (next.includes("all") || next.length === 0) {
      next = ["all"];
    }

    if (targetGradesHidden) {
      targetGradesHidden.value = JSON.stringify(next);
    }

    if (targetGradesOptions) {
      targetGradesOptions.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
        const val = (cb.value || "").toString().trim().toLowerCase();
        cb.checked = next.includes(val);
      });
    }

    renderTargetGradeChips(next);
    if (closeOnAll && next.length === 1 && next[0] === "all") {
      closeTargetGradesMenu();
    }
  }

  function renderTargetGradeChips(selected) {
    const vals = Array.isArray(selected) ? selected : getSelectedTargetGrades();
    if (targetGradesChips) targetGradesChips.innerHTML = "";
    if (targetGradesPlaceholder) {
      targetGradesPlaceholder.style.display = vals.length ? "none" : "inline";
    }
    if (!targetGradesChips) return;

    vals.forEach((val) => {
      const chip = document.createElement("span");
      chip.className = "grade-chip";
      chip.setAttribute("data-grade", val);
      chip.innerHTML = `
        <span class="grade-chip-text">${GRADE_LABELS[val] || val}</span>
        <button type="button" class="grade-chip-remove" aria-label="remove">&times;</button>
      `;
      chip.querySelector(".grade-chip-remove").addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const current = getSelectedTargetGrades();
        const next = current.filter((x) => x !== val);
        setSelectedTargetGrades(next);
        saveFormData();
      });
      targetGradesChips.appendChild(chip);
    });
  }

  function openTargetGradesMenu() {
    if (!targetGradesMenu) return;
    targetGradesMenu.classList.add("open");
    targetGradesMenu.setAttribute("aria-hidden", "false");
  }

  function closeTargetGradesMenu() {
    if (!targetGradesMenu) return;
    targetGradesMenu.classList.remove("open");
    targetGradesMenu.setAttribute("aria-hidden", "true");
  }

  function bindTargetGradesMultiSelect() {
    if (!targetGradeField) return;
    if (targetGradesToggle) {
      targetGradesToggle.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!targetGradesMenu) return;
        const isOpen = targetGradesMenu.classList.contains("open");
        if (isOpen) closeTargetGradesMenu();
        else openTargetGradesMenu();
      });
    }
    if (targetGradesClose) {
      targetGradesClose.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        closeTargetGradesMenu();
      });
    }
    if (targetGradesOptions) {
      targetGradesOptions.addEventListener("change", (e) => {
        const cb = e.target;
        if (!cb || cb.tagName !== "INPUT") return;
        const value = (cb.value || "").toString().trim().toLowerCase();
        if (!ALL_GRADE_VALUES.includes(value)) return;

        const current = new Set(getSelectedTargetGrades());

        if (value === "all") {
          if (cb.checked) {
            setSelectedTargetGrades(["all"], { closeOnAll: true });
          } else {
            setSelectedTargetGrades([]);
          }
          saveFormData();
          return;
        }

        current.delete("all");
        if (cb.checked) current.add(value);
        else current.delete(value);
        const next = Array.from(current);
        setSelectedTargetGrades(next);
        saveFormData();
      });
    }

    document.addEventListener("click", (e) => {
      if (!targetGradesMenu || !targetGradesMenu.classList.contains("open")) return;
      const inside = targetGradeField.contains(e.target);
      if (!inside) closeTargetGradesMenu();
    });

    setSelectedTargetGrades(getSelectedTargetGrades());
  }

  function saveFormData() {
    if (!formCreator) return;
    if (editingFormLink) return;
    if (isHydratingForm) return;
    const targetGrades = getSelectedTargetGrades();
    const formData = {
      topic: document.getElementById("topic")?.value || "",
      description: document.getElementById("description")?.value || "",
      expiry: document.getElementById("expiry")?.value || "",
      targetGrades,
      questions: Array.from(document.querySelectorAll(".question"))
        .map((q) => {
          const questionText = q.querySelector(".question-text")?.value || "";
          const questionType = q.querySelector(".question-type")?.value || "";
          const options = Array.from(q.querySelectorAll(".option")).map(
            (opt) => opt.value
          );
          const correctAnswer = q.querySelector(".correct-answer")?.value || "";
          const points = parseInt(
            q.querySelector(".question-points")?.value || "0"
          );
          const hasPoints =
            q.querySelector(".question-has-points")?.checked === true;
          return {
            questionText,
            questionType,
            options,
            correctAnswer,
            points,
            hasPoints,
          };
        })
        .filter((q) => q.questionText && q.questionType),
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(formData));
  }

  function loadFormData() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (!saved) return false;
      const formData = JSON.parse(saved);

      isHydratingForm = true;

      if (document.getElementById("topic"))
        document.getElementById("topic").value = formData.topic || "";
      if (document.getElementById("description"))
        document.getElementById("description").value =
          formData.description || "";
      if (document.getElementById("expiry"))
        document.getElementById("expiry").value = formData.expiry || "";
      if (Array.isArray(formData.targetGrades)) {
        setSelectedTargetGrades(formData.targetGrades);
      } else {
        setSelectedTargetGrades(["all"]);
      }

      if (
        formData.questions &&
        formData.questions.length > 0 &&
        questionsContainer
      ) {
        questionsContainer.innerHTML = "";
        formData.questions.forEach((qData, index) => {
          const questionDiv = document.createElement("div");
          questionDiv.className = "question question-card";
          questionDiv.innerHTML = `
                        <div class="question-header">
                          <span class="question-number">سؤال ${index + 1}</span>
                          <button type="button" class="remove-question" aria-label="remove">×</button>
                        </div>
                        <label>نوع السؤال:</label>
                        <select class="question-type" required>
                            <option value="" disabled>اختر خياراً</option>
                            <option value="true-false" ${qData.questionType === "true-false"
              ? "selected"
              : ""
            }>صحيح/خطأ</option>
                            <option value="multiple-choice" ${qData.questionType === "multiple-choice"
              ? "selected"
              : ""
            }>اختيارات متعددة</option>
                        </select>
                        <div class="question-fields"></div>
                    `;
          const typeSelect = questionDiv.querySelector(".question-type");
          const fieldsContainer = questionDiv.querySelector(".question-fields");

          if (qData.questionType === "true-false") {
            fieldsContainer.innerHTML = `
                            <div class="q-grid">
                              <div class="q-field">
                                <label>نص السؤال:</label>
                                <input type="text" class="question-text" value="${qData.questionText}" required>
                              </div>
                              <div class="q-field q-answer">
                                <label>الإجابة الصحيحة:</label>
                                <select class="correct-answer">
                                    <option value="True" ${qData.correctAnswer === "True" ? "selected" : ""}>صحيح</option>
                                    <option value="False" ${qData.correctAnswer === "False" ? "selected" : ""}>خطأ</option>
                                </select>
                              </div>
                              <div class="q-field q-points">
                                <div class="points-row">
                                  <label class="has-points-toggle">
                                    <input type="checkbox" class="question-has-points" ${qData.hasPoints === true ? "checked" : ""}>
                                    <span>مع نقاط</span>
                                  </label>
                                  <input type="number" class="question-points" value="${typeof qData.points === "number" ? qData.points : 0}">
                                </div>
                              </div>
                            </div>
                        `;
            const hpCb = fieldsContainer.querySelector(".question-has-points");
            const ptsInp = fieldsContainer.querySelector(".question-points");
            if (hpCb && ptsInp) {
              hpCb.addEventListener("change", (e) => {
                if (e.target.checked) {
                  ptsInp.required = true;
                  ptsInp.setAttribute("min", "1");
                  ptsInp.value = ptsInp.value || "10";
                  ptsInp.style.display = "";
                } else {
                  ptsInp.removeAttribute("required");
                  ptsInp.removeAttribute("min");
                  ptsInp.value = "0";
                  ptsInp.style.display = "none";
                }
              });
              if (qData.hasPoints === true) {
                ptsInp.required = true;
                ptsInp.setAttribute("min", "1");
                ptsInp.style.display = "";
              } else {
                ptsInp.style.display = "none";
              }
            }
          } else {
            fieldsContainer.innerHTML = `
                            <div class="q-grid">
                              <div class="q-field">
                                <label>نص السؤال:</label>
                                <input type="text" class="question-text" value="${qData.questionText}" required>
                              </div>
                              <div class="q-field q-options">
                                <label>الاختيارات:</label>
                                <div class="options-grid">
                                  <input type="text" class="option" value="${qData.options[0] || ""}" required placeholder="الخيار 1">
                                  <input type="text" class="option" value="${qData.options[1] || ""}" required placeholder="الخيار 2">
                                  <input type="text" class="option" value="${qData.options[2] || ""}" required placeholder="الخيار 3">
                                  <input type="text" class="option" value="${qData.options[3] || ""}" required placeholder="الخيار 4">
                                </div>
                              </div>
                              <div class="q-field q-answer">
                                <label>الإجابة الصحيحة:</label>
                                <select class="correct-answer">
                                  <option value="1" ${qData.correctAnswer === "1" ? "selected" : ""}>الخيار 1</option>
                                  <option value="2" ${qData.correctAnswer === "2" ? "selected" : ""}>الخيار 2</option>
                                  <option value="3" ${qData.correctAnswer === "3" ? "selected" : ""}>الخيار 3</option>
                                  <option value="4" ${qData.correctAnswer === "4" ? "selected" : ""}>الخيار 4</option>
                                </select>
                              </div>
                              <div class="q-field q-points">
                                <div class="points-row">
                                  <label class="has-points-toggle">
                                    <input type="checkbox" class="question-has-points" ${qData.hasPoints ? "checked" : ""}>
                                    <span>مع نقاط</span>
                                  </label>
                                  <input type="number" class="question-points" value="${qData.points || 10}">
                                </div>
                              </div>
                            </div>
                        `;
            const hpCb = fieldsContainer.querySelector(".question-has-points");
            const ptsInp = fieldsContainer.querySelector(".question-points");
            if (hpCb && ptsInp) {
              hpCb.addEventListener("change", (e) => {
                if (e.target.checked) {
                  ptsInp.required = true;
                  ptsInp.setAttribute("min", "1");
                  ptsInp.value = ptsInp.value || "10";
                  ptsInp.style.display = "";
                } else {
                  ptsInp.removeAttribute("required");
                  ptsInp.removeAttribute("min");
                  ptsInp.value = "0";
                  ptsInp.style.display = "none";
                }
              });
              if (qData.hasPoints === true) {
                ptsInp.required = true;
                ptsInp.setAttribute("min", "1");
                ptsInp.style.display = "";
              } else {
                ptsInp.style.display = "none";
              }
            }
          }

          typeSelect.addEventListener("change", (e) => {
            const fieldsContainer =
              questionDiv.querySelector(".question-fields");
            fieldsContainer.innerHTML = "";
            if (e.target.value === "true-false") {
              fieldsContainer.innerHTML = `
                                <div class="q-grid">
                                  <div class="q-field">
                                    <label>نص السؤال:</label>
                                    <input type="text" class="question-text" required>
                                  </div>
                                  <div class="q-field q-answer">
                                    <label>الإجابة الصحيحة:</label>
                                    <select class="correct-answer">
                                      <option value="True">صحيح</option>
                                      <option value="False">خطأ</option>
                                    </select>
                                  </div>
                                  <div class="q-field q-points">
                                   
                                    <div class="points-row">
                                      <label class="has-points-toggle">
                                        <input type="checkbox" class="question-has-points">
                                        <span>مع نقاط</span>
                                      </label>
                                      <input type="number" class="question-points" value="0">
                                    </div>
                                  </div>
                                </div>
                            `;
              const hpCb = fieldsContainer.querySelector(
                ".question-has-points"
              );
              const ptsInp = fieldsContainer.querySelector(".question-points");
              if (hpCb && ptsInp) {
                ptsInp.setAttribute("min", "1");
                hpCb.addEventListener("change", (evt) => {
                  if (evt.target.checked) {
                    ptsInp.required = true;
                    ptsInp.setAttribute("min", "1");
                    ptsInp.value = ptsInp.value || "10";
                    ptsInp.style.display = "";
                  } else {
                    ptsInp.removeAttribute("required");
                    ptsInp.removeAttribute("min");
                    ptsInp.value = "0";
                    ptsInp.style.display = "none";
                  }
                });
                ptsInp.style.display = "none";
                ptsInp.value = "0";
                ptsInp.removeAttribute("required");
                ptsInp.removeAttribute("min");
              }
            } else if (e.target.value === "multiple-choice") {
              fieldsContainer.innerHTML = `
                                <div class="q-grid">
                                  <div class="q-field">
                                    <label>نص السؤال:</label>
                                    <input type="text" class="question-text" required>
                                  </div>
                                  <div class="q-field q-options">
                                    <label>الاختيارات:</label>
                                    <div class="options-grid">
                                      <input type="text" class="option" required placeholder="الخيار 1">
                                      <input type="text" class="option" required placeholder="الخيار 2">
                                      <input type="text" class="option" required placeholder="الخيار 3">
                                      <input type="text" class="option" required placeholder="الخيار 4">
                                    </div>
                                  </div>
                                  <div class="q-field q-answer">
                                    <label>الإجابة الصحيحة:</label>
                                    <select class="correct-answer">
                                      <option value="1">الخيار 1</option>
                                      <option value="2">الخيار 2</option>
                                      <option value="3">الخيار 3</option>
                                      <option value="4">الخيار 4</option>
                                    </select>
                                  </div>
                                  <div class="q-field q-points">
                                   
                                    <div class="points-row">
                                      <label class="has-points-toggle">
                                        <input type="checkbox" class="question-has-points">
                                        <span>مع نقاط</span>
                                      </label>
                                      <input type="number" class="question-points" value="0">
                                    </div>
                                  </div>
                                </div>
                            `;
              const hpCb = fieldsContainer.querySelector(
                ".question-has-points"
              );
              const ptsInp = fieldsContainer.querySelector(".question-points");
              if (hpCb && ptsInp) {
                ptsInp.setAttribute("min", "1");
                hpCb.addEventListener("change", (evt) => {
                  if (evt.target.checked) {
                    ptsInp.required = true;
                    ptsInp.setAttribute("min", "1");
                    ptsInp.value = ptsInp.value || "10";
                    ptsInp.style.display = "";
                  } else {
                    ptsInp.removeAttribute("required");
                    ptsInp.removeAttribute("min");
                    ptsInp.value = "0";
                    ptsInp.style.display = "none";
                  }
                });
                ptsInp.style.display = "none";
                ptsInp.value = "0";
                ptsInp.removeAttribute("required");
                ptsInp.removeAttribute("min");
              }
            }
          });

          questionDiv
            .querySelector(".remove-question")
            .addEventListener("click", () => {
              questionsContainer.removeChild(questionDiv);
              saveFormData();
              refreshQuestionNumbers();
            });

          questionsContainer.appendChild(questionDiv);
        });

        refreshQuestionNumbers();
      }
      return true;
    } catch (error) {
      console.error("Error loading form data:", error);
      return false;
    } finally {
      isHydratingForm = false;
    }
  }

  function resetCreateModalFields() {
    if (document.getElementById("topic")) document.getElementById("topic").value = "";
    if (document.getElementById("description"))
      document.getElementById("description").value = "";
    if (document.getElementById("expiry")) document.getElementById("expiry").value = "";
    if (targetGradeField) setSelectedTargetGrades(["all"]);
    if (questionsContainer) questionsContainer.innerHTML = "";
    questions = [];
  }

  function clearFormData() {
    localStorage.removeItem(STORAGE_KEY);
  }

  function closeModal() {
    if (formModal) {
      formModal.style.display = "none";
      formModal.classList.remove("active");
      document.body.style.overflow = "auto";
    }
    editingFormLink = null;
  }

  function setModalMode(isEdit) {
    const titleEl = formModal ? formModal.querySelector(".modal-header h2") : null;
    const submitBtn = formCreator ? formCreator.querySelector('button[type="submit"]') : null;
    if (modalCopyLinkBtn) {
      modalCopyLinkBtn.style.display = isEdit ? "inline-flex" : "none";
    }
    if (titleEl) {
      titleEl.innerHTML = isEdit
        ? '<i class="fas fa-pen"></i> تعديل نموذج'
        : '<i class="fas fa-plus-circle"></i> إنشاء نموذج';
    }
    if (submitBtn) {
      submitBtn.innerHTML = isEdit
        ? '<i class="fas fa-save"></i> حفظ التعديلات'
        : '<i class="fas fa-check"></i> إرسال النموذج';
    }
  }

  bindTargetGradesMultiSelect();

  if (modalCopyLinkBtn) {
    modalCopyLinkBtn.addEventListener("click", async () => {
      if (!editingFormLink) return;
      try {
        window.copyFormLink(editingFormLink);
      } catch (e) {
        const baseUrl = window.location.origin;
        const fullLink = `${baseUrl}/form/${editingFormLink}`;
        await navigator.clipboard.writeText(fullLink);
      }
    });
  }

  async function openModal() {
    if (!formModal) return false;
    if (typeof window.ensureSessionValid === "function") {
      const ok = await window.ensureSessionValid();
      if (!ok) return false;
    }
    formModal.style.display = "block";
    formModal.classList.add("active");
    document.body.style.overflow = "hidden";
    return true;
  }

  async function openEditForm(formLink) {
    const link = (formLink || "").toString().trim();
    if (!link) return;
    if (!formCreator) return;

    try {
      isHydratingForm = true;
      const res = await fetch(`/api/forms/${encodeURIComponent(link)}`, {
        credentials: "include",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.message || "تعذر تحميل بيانات النموذج");
      }

      editingFormLink = link;
      setModalMode(true);
      const opened = await openModal();
      if (!opened) return;

      if (document.getElementById("topic")) {
        document.getElementById("topic").value = data.topic || "";
      }
      if (document.getElementById("description")) {
        document.getElementById("description").value = data.description || "";
      }
      if (document.getElementById("expiry")) {
        const exp = data.expiry ? new Date(data.expiry) : null;
        if (exp && !Number.isNaN(exp.getTime())) {
          const localIso = new Date(exp.getTime() - exp.getTimezoneOffset() * 60000)
            .toISOString()
            .slice(0, 16);
          document.getElementById("expiry").value = localIso;
        } else {
          document.getElementById("expiry").value = "";
        }
      }

      if (targetGradeField) {
        const allowed = Array.isArray(data.allowedGrades) ? data.allowedGrades : [];
        const normalized = allowed.length > 0 ? allowed : [data.targetGrade || "all"];
        setSelectedTargetGrades(normalized);
      }

      if (questionsContainer) {
        questionsContainer.innerHTML = "";
        const qs = Array.isArray(data.questions) ? data.questions : [];
        qs.forEach((qData, index) => {
          const questionDiv = document.createElement("div");
          questionDiv.className = "question question-card";
          const qType = qData.questionType || "multiple-choice";
          questionDiv.innerHTML = `
                <div class="question-header">
                    <span class="question-number">سؤال ${index + 1}</span>
                    <button type="button" class="remove-question" aria-label="remove">×</button>
                </div>
                <label>نوع السؤال:</label>
                <select class="question-type" required>
                    <option value="" disabled>اختر خياراً</option>
                    <option value="true-false" ${qType === "true-false" ? "selected" : ""}>صحيح/خطأ</option>
                    <option value="multiple-choice" ${qType === "multiple-choice" ? "selected" : ""}>اختيارات متعددة</option>
                </select>
                <div class="question-fields"></div>
          `;

          const typeSelect = questionDiv.querySelector(".question-type");
          const fieldsContainer = questionDiv.querySelector(".question-fields");

          const hasPoints = typeof qData.points === "number" ? qData.points > 0 : false;
          const pointsValue = typeof qData.points === "number" ? qData.points : 0;

          if (qType === "true-false") {
            fieldsContainer.innerHTML = `
                <div class="q-grid">
                  <div class="q-field">
                    <label>نص السؤال:</label>
                    <input type="text" class="question-text" value="${(qData.questionText || "").replace(/"/g, "&quot;")}" required>
                  </div>
                  <div class="q-field q-answer">
                    <label>الإجابة الصحيحة:</label>
                    <select class="correct-answer">
                      <option value="True" ${(qData.correctAnswer === "True" || qData.correctAnswerIndex === 0) ? "selected" : ""}>صحيح</option>
                      <option value="False" ${(qData.correctAnswer === "False" || qData.correctAnswerIndex === 1) ? "selected" : ""}>خطأ</option>
                    </select>
                  </div>
                  <div class="q-field q-points">
                   
                    <div class="points-row">
                      <label class="has-points-toggle">
                        <input type="checkbox" class="question-has-points" ${hasPoints ? "checked" : ""}>
                        <span>مع نقاط</span>
                      </label>
                      <input type="number" class="question-points" value="${pointsValue}">
                    </div>
                  </div>
                </div>
            `;
          } else {
            const opts = Array.isArray(qData.options) ? qData.options : [];
            const correctIdx = typeof qData.correctAnswerIndex === "number" ? qData.correctAnswerIndex : (typeof qData.correctAnswer === "number" ? qData.correctAnswer : 0);
            fieldsContainer.innerHTML = `
                <div class="q-grid">
                  <div class="q-field">
                    <label>نص السؤال:</label>
                    <input type="text" class="question-text" value="${(qData.questionText || "").replace(/"/g, "&quot;")}" required>
                  </div>
                  <div class="q-field q-options">
                    <label>الاختيارات:</label>
                    <div class="options-grid">
                      <input type="text" class="option" value="${(opts[0] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 1">
                      <input type="text" class="option" value="${(opts[1] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 2">
                      <input type="text" class="option" value="${(opts[2] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 3">
                      <input type="text" class="option" value="${(opts[3] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 4">
                    </div>
                  </div>
                  <div class="q-field q-answer">
                    <label>الإجابة الصحيحة:</label>
                    <select class="correct-answer">
                      <option value="1" ${correctIdx === 0 ? "selected" : ""}>الخيار 1</option>
                      <option value="2" ${correctIdx === 1 ? "selected" : ""}>الخيار 2</option>
                      <option value="3" ${correctIdx === 2 ? "selected" : ""}>الخيار 3</option>
                      <option value="4" ${correctIdx === 3 ? "selected" : ""}>الخيار 4</option>
                    </select>
                  </div>
                  <div class="q-field q-points">
                   
                    <div class="points-row">
                      <label class="has-points-toggle">
                        <input type="checkbox" class="question-has-points" ${hasPoints ? "checked" : ""}>
                        <span>مع نقاط</span>
                      </label>
                      <input type="number" class="question-points" value="${pointsValue}">
                    </div>
                  </div>
                </div>
            `;
          }

          const hpCb = fieldsContainer.querySelector(".question-has-points");
          const ptsInp = fieldsContainer.querySelector(".question-points");
          if (hpCb && ptsInp) {
            hpCb.addEventListener("change", (e) => {
              if (e.target.checked) {
                ptsInp.required = true;
                ptsInp.setAttribute("min", "1");
                ptsInp.value = ptsInp.value || "10";
                ptsInp.style.display = "";
              } else {
                ptsInp.removeAttribute("required");
                ptsInp.removeAttribute("min");
                ptsInp.value = "0";
                ptsInp.style.display = "none";
              }
            });
            if (hasPoints) {
              ptsInp.required = true;
              ptsInp.setAttribute("min", "1");
              ptsInp.style.display = "";
            } else {
              ptsInp.style.display = "none";
            }
          }

          if (typeSelect) {
            const cached = {
              questionText: (qData.questionText || "").toString(),
              multipleChoiceOptions: Array.isArray(qData.options) ? qData.options.slice(0, 4) : ["", "", "", ""],
              multipleChoiceCorrectIdx:
                typeof qData.correctAnswerIndex === "number"
                  ? qData.correctAnswerIndex
                  : typeof qData.correctAnswer === "number"
                    ? qData.correctAnswer
                    : 0,
              trueFalseCorrect:
                qType === "true-false"
                  ? (qData.correctAnswer === "False" || qData.correctAnswerIndex === 1 ? "False" : "True")
                  : "True",
              hasPoints,
              pointsValue,
            };

            const readCurrentIntoCache = () => {
              const fc = questionDiv.querySelector(".question-fields");
              if (!fc) return;
              const qt = fc.querySelector(".question-text");
              if (qt) cached.questionText = (qt.value || "").toString();
              const hp = fc.querySelector(".question-has-points");
              const pi = fc.querySelector(".question-points");
              if (hp) cached.hasPoints = Boolean(hp.checked);
              if (pi) cached.pointsValue = parseInt(pi.value, 10) || 0;
              const typeNow = typeSelect.value;
              if (typeNow === "multiple-choice") {
                cached.multipleChoiceOptions = Array.from(
                  fc.querySelectorAll(".option")
                ).map((o) => (o.value || "").toString());
                while (cached.multipleChoiceOptions.length < 4) {
                  cached.multipleChoiceOptions.push("");
                }
                const ca = fc.querySelector(".correct-answer");
                if (ca) cached.multipleChoiceCorrectIdx = Math.max(0, (parseInt(ca.value, 10) || 1) - 1);
              } else if (typeNow === "true-false") {
                const ca = fc.querySelector(".correct-answer");
                if (ca) cached.trueFalseCorrect = ca.value === "False" ? "False" : "True";
              }
            };

            const wirePoints = (fc) => {
              const hpCb = fc.querySelector(".question-has-points");
              const ptsInp = fc.querySelector(".question-points");
              if (!hpCb || !ptsInp) return;
              const applyState = () => {
                if (hpCb.checked) {
                  ptsInp.required = true;
                  ptsInp.setAttribute("min", "1");
                  ptsInp.value = ptsInp.value || "10";
                  ptsInp.style.display = "";
                } else {
                  ptsInp.removeAttribute("required");
                  ptsInp.removeAttribute("min");
                  ptsInp.value = "0";
                  ptsInp.style.display = "none";
                }
              };
              hpCb.addEventListener("change", applyState);
              applyState();
            };

            typeSelect.addEventListener("change", (e) => {
              readCurrentIntoCache();
              const fieldsContainer = questionDiv.querySelector(".question-fields");
              fieldsContainer.innerHTML = "";
              if (e.target.value === "true-false") {
                fieldsContainer.innerHTML = `
                    <div class="q-grid">
                      <div class="q-field">
                        <label>نص السؤال:</label>
                        <input type="text" class="question-text" value="${cached.questionText.replace(/"/g, "&quot;")}" required>
                      </div>
                      <div class="q-field q-answer">
                        <label>الإجابة الصحيحة:</label>
                        <select class="correct-answer">
                          <option value="True" ${cached.trueFalseCorrect === "True" ? "selected" : ""}>صحيح</option>
                          <option value="False" ${cached.trueFalseCorrect === "False" ? "selected" : ""}>خطأ</option>
                        </select>
                      </div>
                      <div class="q-field q-points">
                       
                        <div class="points-row">
                          <label class="has-points-toggle">
                            <input type="checkbox" class="question-has-points" ${cached.hasPoints ? "checked" : ""}>
                            <span>مع نقاط</span>
                          </label>
                          <input type="number" class="question-points" value="${cached.hasPoints ? Math.max(1, parseInt(cached.pointsValue, 10) || 10) : 0}">
                        </div>
                      </div>
                    </div>
                `;
                wirePoints(fieldsContainer);
              } else {
                fieldsContainer.innerHTML = `
                    <div class="q-grid">
                      <div class="q-field">
                        <label>نص السؤال:</label>
                        <input type="text" class="question-text" value="${cached.questionText.replace(/"/g, "&quot;")}" required>
                      </div>
                      <div class="q-field q-options">
                        <label>الاختيارات:</label>
                        <div class="options-grid">
                          <input type="text" class="option" value="${(cached.multipleChoiceOptions[0] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 1">
                          <input type="text" class="option" value="${(cached.multipleChoiceOptions[1] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 2">
                          <input type="text" class="option" value="${(cached.multipleChoiceOptions[2] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 3">
                          <input type="text" class="option" value="${(cached.multipleChoiceOptions[3] || "").replace(/"/g, "&quot;")}" required placeholder="الخيار 4">
                        </div>
                      </div>
                      <div class="q-field q-answer">
                        <label>الإجابة الصحيحة:</label>
                        <select class="correct-answer">
                          <option value="1" ${cached.multipleChoiceCorrectIdx === 0 ? "selected" : ""}>الخيار 1</option>
                          <option value="2" ${cached.multipleChoiceCorrectIdx === 1 ? "selected" : ""}>الخيار 2</option>
                          <option value="3" ${cached.multipleChoiceCorrectIdx === 2 ? "selected" : ""}>الخيار 3</option>
                          <option value="4" ${cached.multipleChoiceCorrectIdx === 3 ? "selected" : ""}>الخيار 4</option>
                        </select>
                      </div>
                      <div class="q-field q-points">
                       
                        <div class="points-row">
                          <label class="has-points-toggle">
                            <input type="checkbox" class="question-has-points" ${cached.hasPoints ? "checked" : ""}>
                            <span>مع نقاط</span>
                          </label>
                          <input type="number" class="question-points" value="${cached.hasPoints ? Math.max(1, parseInt(cached.pointsValue, 10) || 10) : 0}">
                        </div>
                      </div>
                    </div>
                `;
                wirePoints(fieldsContainer);
              }
            });
          }

          questionDiv
            .querySelector(".remove-question")
            .addEventListener("click", () => {
              questionsContainer.removeChild(questionDiv);
              refreshQuestionNumbers();
            });

          questionsContainer.appendChild(questionDiv);
        });

        refreshQuestionNumbers();
      }
    } catch (err) {
      await Swal.fire({
        title: "خطأ",
        text: err.message || "تعذر فتح النموذج للتعديل",
        icon: "error",
        confirmButtonText: "حسنًا",
      });
    } finally {
      isHydratingForm = false;
    }
  }

  if (createFormButton) {
    createFormButton.addEventListener("click", async () => {
      editingFormLink = null;
      setModalMode(false);
      const opened = await openModal();
      if (!opened) return;
      clearFormData();
      resetCreateModalFields();
      if (document.getElementById("topic")) {
        document.getElementById("topic").focus();
      }
    });
  }

  if (formCreator) {
    formCreator.addEventListener("input", saveFormData);
    formCreator.addEventListener("change", saveFormData);
  }

  window.addEventListener("beforeunload", saveFormData);

  document.addEventListener("keydown", (e) => {
    if (
      e.key === "Escape" &&
      formModal &&
      formModal.style.display === "block"
    ) {
      closeModal();
    }
  });

  if (closeButton) {
    closeButton.addEventListener("click", closeModal);
  }

  const cancelButton = formModal
    ? formModal.querySelector(".cancel-btn")
    : null;
  if (cancelButton) {
    cancelButton.addEventListener("click", closeModal);
  }

  if (formModal) {
    formModal.addEventListener("click", (e) => {
      if (e.target === formModal) {
        closeModal();
      }
    });
  }

  if (addQuestionButton) {
    addQuestionButton.addEventListener("click", () => {
      if (!questionsContainer) return;

      const questionDiv = document.createElement("div");
      questionDiv.className = "question question-card";

      questionDiv.innerHTML = `
                <div class="question-header">
                    <span class="question-number">سؤال</span>
                    <button type="button" class="remove-question" aria-label="remove">×</button>
                </div>
                <label>نوع السؤال:</label>
                <select class="question-type" required>
                    <option value="" disabled selected>اختر خياراً</option>
                    <option value="true-false">صحيح/خطأ</option>
                    <option value="multiple-choice">اختيارات متعددة</option>
                </select>
                <div class="question-fields"></div>
            `;

      questionDiv
        .querySelector(".question-type")
        .addEventListener("change", (e) => {
          const fieldsContainer = questionDiv.querySelector(".question-fields");
          fieldsContainer.innerHTML = "";

          if (e.target.value === "true-false") {
            fieldsContainer.innerHTML = `
                        <div class="q-grid">
                          <div class="q-field">
                            <label>نص السؤال:</label>
                            <input type="text" class="question-text" required>
                          </div>
                          <div class="q-field q-answer">
                            <label>الإجابة الصحيحة:</label>
                            <select class="correct-answer">
                              <option value="True">صحيح</option>
                              <option value="False">خطأ</option>
                            </select>
                          </div>
                          <div class="q-field q-points">
                           
                            <div class="points-row">
                              <label class="has-points-toggle">
                                <input type="checkbox" class="question-has-points">
                                <span>مع نقاط</span>
                              </label>
                              <input type="number" class="question-points" value="0">
                            </div>
                          </div>
                        </div>
                    `;

            const hasPointsCheckbox = fieldsContainer.querySelector(
              ".question-has-points"
            );
            const pointsInput = fieldsContainer.querySelector(".question-points");

            hasPointsCheckbox.addEventListener("change", (e) => {
              if (e.target.checked) {
                pointsInput.required = true;
                pointsInput.setAttribute("min", "1");
                pointsInput.value = pointsInput.value || "10";
                pointsInput.style.display = "";
              } else {
                pointsInput.removeAttribute("required");
                pointsInput.removeAttribute("min");
                pointsInput.value = "0";
                pointsInput.style.display = "none";
              }
            });

            pointsInput.style.display = "none";
            pointsInput.value = "0";
            pointsInput.removeAttribute("required");
            pointsInput.removeAttribute("min");
          } else if (e.target.value === "multiple-choice") {
            fieldsContainer.innerHTML = `
                        <div class="q-grid">
                          <div class="q-field">
                            <label>نص السؤال:</label>
                            <input type="text" class="question-text" required>
                          </div>
                          <div class="q-field q-options">
                            <label>الاختيارات:</label>
                            <div class="options-grid">
                              <input type="text" class="option" required placeholder="الخيار 1">
                              <input type="text" class="option" required placeholder="الخيار 2">
                              <input type="text" class="option" required placeholder="الخيار 3">
                              <input type="text" class="option" required placeholder="الخيار 4">
                            </div>
                          </div>
                          <div class="q-field q-answer">
                            <label>الإجابة الصحيحة:</label>
                            <select class="correct-answer">
                              <option value="1">الخيار 1</option>
                              <option value="2">الخيار 2</option>
                              <option value="3">الخيار 3</option>
                              <option value="4">الخيار 4</option>
                            </select>
                          </div>
                          <div class="q-field q-points">
                           
                            <div class="points-row">
                              <label class="has-points-toggle">
                                <input type="checkbox" class="question-has-points">
                                <span>مع نقاط</span>
                              </label>
                              <input type="number" class="question-points" value="0">
                            </div>
                          </div>
                        </div>
                    `;

            const hasPointsCheckbox = fieldsContainer.querySelector(
              ".question-has-points"
            );
            const pointsInput = fieldsContainer.querySelector(".question-points");

            hasPointsCheckbox.addEventListener("change", (e) => {
              if (e.target.checked) {
                pointsInput.required = true;
                pointsInput.setAttribute("min", "1");
                pointsInput.value = pointsInput.value || "10";
                pointsInput.style.display = "";
              } else {
                pointsInput.removeAttribute("required");
                pointsInput.removeAttribute("min");
                pointsInput.value = "0";
                pointsInput.style.display = "none";
              }
            });

            pointsInput.style.display = "none";
            pointsInput.value = "0";
            pointsInput.removeAttribute("required");
            pointsInput.removeAttribute("min");
          }
        });

      questionDiv
        .querySelector(".remove-question")
        .addEventListener("click", () => {
          questionsContainer.removeChild(questionDiv);
          refreshQuestionNumbers();
        });

      questionsContainer.appendChild(questionDiv);
      refreshQuestionNumbers();
    });
  }

  if (formCreator) {
    formCreator.addEventListener("submit", async (e) => {
      e.preventDefault();

      const questionElements = document.querySelectorAll(".question");
      if (questionElements.length === 0) {
        Swal.fire({
          text: "لا يمكن إنشاء نموذج بدون سؤال واحد على الأقل",
          icon: "error",
          confirmButtonText: "حسنًا",
        });
        return;
      }

      const topic = document.getElementById("topic").value.trim();
      const description = document.getElementById("description").value.trim();
      const expiry = document.getElementById("expiry").value;

      const questions = Array.from(document.querySelectorAll(".question")).map(
        (q) => {
          const questionText = q.querySelector(".question-text").value;
          const questionType = q.querySelector(".question-type").value;
          const options = Array.from(q.querySelectorAll(".option")).map(
            (opt) => opt.value
          );
          let correctAnswer = q.querySelector(".correct-answer").value;
          const pointsInput = q.querySelector(".question-points");
          const hasPointsCheckbox = q.querySelector(".question-has-points");
          const hasPoints = hasPointsCheckbox.checked;
          const pointsValue = hasPoints ? parseInt(pointsInput.value, 10) || 10 : 0;

          if (questionType === "multiple-choice") {
            correctAnswer = parseInt(correctAnswer, 10) - 1;
          }

          return {
            questionText,
            questionType,
            options,
            correctAnswer,
            points: pointsValue,
            hasPoints,
          };
        }
      );

      const submitBtn = formCreator.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML =
          editingFormLink
            ? '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span><span style="margin-right:8px">جاري الحفظ...</span>'
            : '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span><span style="margin-right:8px">جاري الإنشاء...</span>';
      }

      try {
        const selectedGrades = getSelectedTargetGrades();
        const payloadTarget = selectedGrades.includes("all") ? "all" : "all";
        const payloadAllowed = selectedGrades.includes("all") ? [] : selectedGrades;
        const payload = {
          topic,
          description: description || "",
          expiry: expiry || null,
          questions,
          targetGrade: payloadTarget,
          allowedGrades: payloadAllowed,
          status: "published",
        };

        const response = await fetch(
          editingFormLink
            ? `/api/forms/${encodeURIComponent(editingFormLink)}`
            : "/api/forms",
          {
            method: editingFormLink ? "PUT" : "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          }
        );

        const data = await response.json().catch(() => ({}));
        if (!response.ok || data.success === false) {
          throw new Error(data.message || "حدث خطأ أثناء حفظ النموذج");
        }

        if (!editingFormLink) {
          clearFormData();
        }

        if (formCreator) {
          formCreator.reset();
        }
        if (questionsContainer) {
          questionsContainer.innerHTML = "";
        }

        await Swal.fire({
          text: editingFormLink ? "تم حفظ التعديلات." : "تم إنشاء النموذج!.",
          icon: "success",
          confirmButtonText: "حسنًا",
        });

        closeModal();
        if (formsList) {
          loadForms();
        } else {
          window.location.reload();
        }
      } catch (error) {
        Swal.fire({
          text: error.message || "حدث خطأ أثناء إنشاء النموذج",
          icon: "error",
          confirmButtonText: "حسنًا",
        });
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          setModalMode(Boolean(editingFormLink));
        }
      }
    });
  }

  function CopyLinkButton(formDiv, formLink) {
    const baseUrl = `${window.location.origin}/form/`;
    const copyButton = document.createElement("button");
    copyButton.textContent = " 📋 نسخ رابط النموذج";
    copyButton.className = "copy-link-btn";

    copyButton.addEventListener("click", () => {
      const fullLink = `${baseUrl}${formLink}`;
      navigator.clipboard
        .writeText(fullLink)
        .then(() => {
          Swal.fire({
            text: "تم نسخ الرابط بنجاح!",
            icon: "success",
            confirmButtonText: "حسنًا",
          });
        })
        .catch((err) => {
          Swal.fire({
            text: "حدث خطأ أثناء نسخ الرابط.",
            icon: "error",
            confirmButtonText: "حسنًا",
          });
          console.error("Error copying link:", err);
        });
    });

    formDiv.appendChild(copyButton);
  }

  async function loadForms() {
    if (!formsList) {
      console.error("formsList element not found");
      return;
    }

    formsList.innerHTML = `
            <div class="loading-state">
                <span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span>
                <p>جاري التحميل...</p>
            </div>
        `;

    try {
      const response = await fetch("/api/forms", {
        method: "GET",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });

      console.log("Forms API response status:", response.status);

      if (!response.ok) {
        const errorData = await response
          .json()
          .catch(() => ({ message: "فشل تحميل النماذج" }));
        throw new Error(
          errorData.message || `HTTP ${response.status}: فشل تحميل النماذج`
        );
      }

      const data = await response.json();
      console.log("Forms data received:", data);

      const forms = Array.isArray(data) ? data : data.active || [];
      const expiredForms = data.expired || [];

      const statsEl = document.getElementById("dashboard-stats");
      if (statsEl) {
        const total = forms.length + expiredForms.length;
        statsEl.innerHTML = `
          <div class="stat-card stat-success">
            <div class="stat-icon"><i class="fas fa-check-circle"></i></div>
            <div class="stat-value">${forms.length}</div>
            <div class="stat-label">نشطة</div>
          </div>
          <div class="stat-card stat-warning">
            <div class="stat-icon"><i class="fas fa-clock"></i></div>
            <div class="stat-value">${expiredForms.length}</div>
            <div class="stat-label">منتهية</div>
          </div>
          <div class="stat-card stat-info">
            <div class="stat-icon"><i class="fas fa-layer-group"></i></div>
            <div class="stat-value">${total}</div>
            <div class="stat-label">الإجمالي</div>
          </div>
        `;
      }

      formsList.innerHTML = "";

      if (forms.length === 0 && expiredForms.length === 0) {
        const noFormsDiv = document.createElement("div");
        noFormsDiv.className = "empty-state";
        noFormsDiv.style.cssText =
          "grid-column: 1 / -1; text-align: center; padding: 50px 20px; width: 100%;";
        noFormsDiv.innerHTML = `
                    <i class="fas fa-file-alt"></i>
                    <h3>لا توجد نماذج</h3>
                    <p>لم يتم إنشاء أي نموذج حتى الآن.</p>
                `;
        formsList.appendChild(noFormsDiv);
      } else {
        if (forms.length > 0) {
          const activeTitle = document.createElement("h2");
          activeTitle.className = "section-title";
          activeTitle.innerHTML = `
                        <i class="fas fa-check-circle"></i>
                        النماذج النشطة (${forms.length})
                    `;
          formsList.appendChild(activeTitle);

          const activeSection = document.createElement("div");
          activeSection.className = "forms-section";
          formsList.appendChild(activeSection);

          forms.forEach((form) => {
            renderFormCard(form, activeSection, false);
          });
        }

        if (expiredForms.length > 0) {
          const expiredTitle = document.createElement("h2");
          expiredTitle.className = "section-title";
          expiredTitle.innerHTML = `
                        <i class="fas fa-clock"></i>
                        النماذج المنتهية (${expiredForms.length})
                    `;
          formsList.appendChild(expiredTitle);

          const expiredSection = document.createElement("div");
          expiredSection.className = "forms-section";
          formsList.appendChild(expiredSection);

          expiredForms.forEach((form) => {
            renderFormCard(form, expiredSection, true);
          });
        }
      }
    } catch (error) {
      console.error("Error loading forms:", error);
      const errorDiv = document.createElement("div");
      errorDiv.className = "empty-state";
      errorDiv.style.cssText =
        "grid-column: 1 / -1; text-align: left; padding: 50px 20px; width: 100%; display: flex; flex-direction: column; align-items: flex-start; gap: 15px;";
      errorDiv.innerHTML = `
                <i class="fas fa-exclamation-circle"></i>
                <h3>حدث خطأ</h3>
                <p>${error.message || "تعذر تحميل النماذج. يرجى المحاولة مرة أخرى."
        }</p>
                <button onclick="location.reload()" style="margin-top: 15px; padding: 10px 20px; background: var(--accent); color: var(--dark); border: none; border-radius: 8px; cursor: pointer; font-weight: 600;">
                    إعادة المحاولة
                </button>
            `;
      formsList.innerHTML = "";
      formsList.appendChild(errorDiv);

      if (window.innerWidth <= 768) {
        errorDiv.style.textAlign = "center";
        errorDiv.style.alignItems = "center";
      }
    }
  }

  function renderFormCard(form, container, isExpired) {
    const expiryDate = form.expiry ? new Date(form.expiry) : null;
    const formIdent = (form.link && String(form.link).trim()) ? String(form.link).trim() : (form._id ? String(form._id) : "");
    const allowedGrades = Array.isArray(form.allowedGrades) ? form.allowedGrades : [];
    const normalizedGrades = allowedGrades
      .map((g) => (g || "").toString().trim().toLowerCase())
      .filter((g) => ALL_GRADE_VALUES.includes(g) && g !== "all");
    const targetRaw = (form.targetGrade || "all").toString().trim().toLowerCase();
    const displayGrades =
      normalizedGrades.length > 0
        ? normalizedGrades
            .map((g) => GRADE_LABELS[g] || g)
            .filter(Boolean)
            .join("، ")
        : GRADE_LABELS[targetRaw] || GRADE_LABELS.all;
    const formDiv = document.createElement("div");
    formDiv.className = isExpired ? "form-card expired" : "form-card";
    const showDeactivate = !isExpired && form.status === "published";

    formDiv.innerHTML = `
            <div class="form-header">
                <div class="form-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <span class="form-status ${isExpired
        ? "status-expired"
        : form.status === "published"
          ? "status-published"
          : "status-draft"
      }">
                    ${isExpired
        ? "منتهي"
        : form.status === "published"
          ? "منشور"
          : "مسودة"
      }
                </span>
            </div>
            <h3 class="form-title">${form.topic}</h3>
            <p class="form-description">${form.description || "لا يوجد وصف"}</p>
            <div class="form-meta">
                <div class="meta-item">
                    <span class="meta-label">الفئة:</span>
                    <span class="meta-value">${displayGrades}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">الأسئلة:</span>
                    <span class="meta-value">${form.questions?.length || 0
      }</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">ينتهي:</span>
                    <span class="meta-value">${expiryDate
        ? expiryDate.toLocaleDateString("ar-EG")
        : "بدون موعد"
      }</span>
                </div>
            </div>
            <div class="form-actions">
                <a href="/form/${formIdent}/leaderboard" target="_blank" class="action-btn view-btn">
                    <i class="fas fa-trophy"></i>
                    لوحة الترتيب
                </a>
                <a href="/form/${formIdent}" target="_blank" class="action-btn view-btn">
                    <i class="fas fa-eye"></i>
                    عرض النموذج
                </a>
                <button class="action-btn copy-btn" data-form-ident="${formIdent}">
                    <i class="fas fa-copy"></i>
                    نسخ
                </button>
                <button class="action-btn edit-btn" data-form-ident="${formIdent}">
                    <i class="fas fa-pen"></i>
                    تعديل
                </button>
                <button class="action-btn reset-user-btn" data-form-ident="${formIdent}">
                    <i class="fas fa-user-clock"></i>
                    إعادة المحاولة للمستخدم
                </button>
                ${showDeactivate
        ? `
                <button class="action-btn deactivate-btn" data-form-ident="${formIdent}">
                    <i class="fas fa-eye-slash"></i>
                    تعطيل
                </button>
                `
        : ""
      }
                ${isExpired
        ? `
                <button class="action-btn reactivate-btn" data-form-ident="${formIdent}">
                    <i class="fas fa-redo"></i>
                    إعادة تفعيل
                </button>
                `
        : ""
      }
                <button class="action-btn delete-btn" data-form-id="${form._id || ""}" data-form-ident="${formIdent}">
                    <i class="fas fa-trash"></i>
                    حذف
                </button>
            </div>
        `;

    container.appendChild(formDiv);

    const copyBtn = formDiv.querySelector(".copy-btn");
    if (copyBtn) {
      copyBtn.addEventListener("click", () => {
        window.copyFormLink(formIdent);
      });
    }

    const editBtn = formDiv.querySelector(".edit-btn");
    if (editBtn) {
      editBtn.addEventListener("click", () => {
        openEditForm(formIdent);
      });
    }

    const deactivateBtn = formDiv.querySelector(".deactivate-btn");
    if (deactivateBtn) {
      deactivateBtn.addEventListener("click", () => {
        window.deactivateForm(formIdent, deactivateBtn);
      });
    }

    const reactivateBtn = formDiv.querySelector(".reactivate-btn");
    if (reactivateBtn) {
      reactivateBtn.addEventListener("click", () => {
        window.reactivateForm(formIdent, reactivateBtn);
      });
    }

    const deleteBtn = formDiv.querySelector(".delete-btn");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", () => {
        deleteFormFromList(form._id || "", formIdent, deleteBtn);
      });
    }

    const resetUserBtn = formDiv.querySelector(".reset-user-btn");
    if (resetUserBtn) {
      resetUserBtn.addEventListener("click", () => {
        window.resetFormForUser(formIdent, resetUserBtn);
      });
    }
  }

  window.resetFormForUser = async function resetFormForUser(formLink, buttonEl) {
    const link = typeof formLink === "string" ? formLink.trim() : "";
    if (!link) return;

    const GRADE_FILTER_OPTIONS = [
      { value: "all", label: "كل الصفوف" },
      { value: "prep1", label: "أولي إعدادي" },
      { value: "prep2", label: "ثانية إعدادي" },
      { value: "prep3", label: "ثالثة إعدادي" },
      { value: "sec1", label: "أولي ثانوي" },
      { value: "sec2", label: "ثانية ثانوي" },
      { value: "sec3", label: "ثالثة ثانوي" },
    ];

    const selected = new Set();
    let currentUsers = [];
    let currentSearch = "";
    let currentGrade = "all";

    const GRADE_LABEL_BY_VALUE = GRADE_FILTER_OPTIONS.reduce((acc, item) => {
      acc[item.value] = item.label;
      return acc;
    }, {});

    const fetchUsers = async ({ search, grade, limit = 4, skip = 0 } = {}) => {
      const params = new URLSearchParams();
      params.set("limit", String(limit));
      params.set("skip", String(skip));
      if (grade && grade !== "all") params.set("grade", grade);
      if (search) params.set("search", search);
      const res = await fetch(`/api/admin/users?${params.toString()}`, {
        credentials: "include",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || data.message || "تعذر تحميل المستخدمين");
      }
      return {
        users: Array.isArray(data.users) ? data.users : [],
        total: typeof data.total === "number" ? data.total : null,
      };
    };

    const renderUserList = (containerEl, countEl) => {
      if (!containerEl) return;
      const rawItems = Array.isArray(currentUsers) ? currentUsers : [];
      const q = (currentSearch || "").toString().trim().toLowerCase();
      const items = q
        ? rawItems.filter((u) => {
            const username = (u?.username || "").toString().toLowerCase();
            const first = (u?.firstName || "").toString().toLowerCase();
            const second = (u?.secondName || "").toString().toLowerCase();
            const phone = (u?.phone || "").toString().toLowerCase();
            const email = (u?.email || "").toString().toLowerCase();
            const full = `${first} ${second}`.trim();
            return (
              username.includes(q) ||
              first.includes(q) ||
              second.includes(q) ||
              full.includes(q) ||
              phone.includes(q) ||
              email.includes(q)
            );
          })
        : rawItems;

      if (countEl) {
        countEl.textContent = selected.size ? `(${selected.size})` : "";
      }

      if (items.length === 0) {
        containerEl.innerHTML = `
          <div style="padding:12px 10px; opacity:.8; text-align:center;">لا يوجد مستخدم</div>
        `;
        return;
      }

      containerEl.innerHTML = items
        .map((u) => {
          const username = (u && u.username ? String(u.username) : "").trim();
          const grade = (u && u.grade ? String(u.grade) : "").trim();
          const fullName = `${u?.firstName || ""} ${u?.secondName || ""}`.trim();
          const isChecked = selected.has(username.toLowerCase());
          return `
            <label style="display:flex; align-items:center; gap:10px; padding:10px 12px; border:1px solid rgba(255,255,255,.12); border-radius:12px; background:rgba(0,0,0,.16); cursor:pointer; direction:ltr;">
              <div style="display:flex; flex-direction:column; gap:2px; min-width:0; flex:1;">
                <div style="font-weight:900; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; text-align:left; direction:ltr;">${
                  fullName || username
                }</div>
                <div style="opacity:.8; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; text-align:left; direction:ltr;">${
                  grade ? `${GRADE_LABEL_BY_VALUE[grade] || grade}` : ""
                }</div>
              </div>
              <input type="checkbox" data-username="${username.replace(/"/g, "&quot;")}" ${
            isChecked ? "checked" : ""
          } style="width:18px; height:18px; accent-color: var(--accent); flex:0 0 auto;" />
            </label>
          `;
        })
        .join("");

      containerEl.querySelectorAll('input[type="checkbox"][data-username]').forEach((cb) => {
        cb.addEventListener("change", (e) => {
          const uname = (e.target?.dataset?.username || "").toString();
          const key = uname.trim().toLowerCase();
          if (!key) return;
          if (e.target.checked) selected.add(key);
          else selected.delete(key);
          if (countEl) {
            countEl.textContent = selected.size ? `(${selected.size})` : "";
          }
        });
      });
    };

    const { value: pickedUsernames } = await Swal.fire({
      title: "إعادة المحاولة للمستخدم",
      html: `
        <div style="display:flex; flex-direction:column; gap:12px; text-align:left;">
          <div style="display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-start;">
            <input id="retakeUserSearch" type="text" placeholder="ابحث بالاسم / الهاتف / الإيميل..." style="flex:1; min-width:220px; padding:10px 12px; border-radius:12px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.2); color:var(--text);" />
            <select id="retakeUserGrade" style="min-width:170px; height:38px; padding:6px 12px 10px; line-height:1.1; border-radius:12px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.2); color:var(--text); cursor:pointer;">
              ${GRADE_FILTER_OPTIONS.map(
                (g) => `<option value="${g.value}">${g.label}</option>`
              ).join("")}
            </select>
          </div>
          <div style="display:flex; align-items:center; justify-content:space-between;">
            <div style="font-weight:800;">اختر مستخدمين</div>
            <div style="font-weight:800; color: var(--accent);" id="retakeSelectedCount"></div>
          </div>
          <div id="retakeUserList" style="display:flex; flex-direction:column; gap:10px; max-height:260px; overflow:auto; padding-right:2px;"></div>
          <div style="opacity:.75; font-size:12px; text-align:left;">سيتم تحميل عدد محدود من المستخدمين. استخدم البحث أو فلتر الصف لإظهار آخرين.</div>
        </div>
      `,
      focusConfirm: false,
      showCancelButton: true,
      confirmButtonText: "إعادة تعيين",
      cancelButtonText: "إلغاء",
      confirmButtonColor: "#f39c12",
      cancelButtonColor: "#666",
      didOpen: async () => {
        const listEl = Swal.getPopup()?.querySelector("#retakeUserList");
        const countEl = Swal.getPopup()?.querySelector("#retakeSelectedCount");
        const searchEl = Swal.getPopup()?.querySelector("#retakeUserSearch");
        const gradeEl = Swal.getPopup()?.querySelector("#retakeUserGrade");

        const load = async () => {
          if (listEl) {
            listEl.innerHTML = `
              <div style="padding:12px 10px; opacity:.9; text-align:center; display:flex; align-items:center; justify-content:center; gap:10px;">
                <span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span>
                <span>جاري التحميل...</span>
              </div>
            `;
          }
          const result = await fetchUsers({
            search: currentSearch,
            grade: currentGrade,
            limit: 10,
            skip: 0,
          });
          currentUsers = result.users;
          renderUserList(listEl, countEl);
        };

        let searchTimer = null;
        if (searchEl) {
          searchEl.addEventListener("input", () => {
            const next = (searchEl.value || "").toString().trim();
            currentSearch = next;
            if (searchTimer) window.clearTimeout(searchTimer);
            searchTimer = window.setTimeout(() => {
              load().catch((e) => {
                if (listEl) {
                  listEl.innerHTML = `<div style="padding:12px 10px; opacity:.85; text-align:center;">${
                    e.message || "خطأ"
                  }</div>`;
                }
              });
            }, 250);
          });
        }

        if (gradeEl) {
          gradeEl.addEventListener("change", () => {
            currentGrade = (gradeEl.value || "all").toString();
            load().catch((e) => {
              if (listEl) {
                listEl.innerHTML = `<div style="padding:12px 10px; opacity:.85; text-align:center;">${
                  e.message || "خطأ"
                }</div>`;
              }
            });
          });
        }

        await load().catch((e) => {
          if (listEl) {
            listEl.innerHTML = `<div style="padding:12px 10px; opacity:.85; text-align:center;">${
              e.message || "خطأ"
            }</div>`;
          }
        });
      },
      preConfirm: () => {
        const usernames = Array.from(selected.values());
        if (usernames.length === 0) {
          Swal.showValidationMessage("اختر مستخدمًا واحدًا على الأقل");
          return false;
        }
        return usernames;
      },
    });

    const usernames = Array.isArray(pickedUsernames) ? pickedUsernames : [];
    if (usernames.length === 0) return;

    const confirm = await Swal.fire({
      title: "تأكيد",
      text: `هل تريد السماح لـ ${usernames.length} مستخدم/مستخدمين بإعادة محاولة هذا النموذج؟`,
      icon: "warning",
      showCancelButton: true,
      confirmButtonText: "نعم",
      cancelButtonText: "إلغاء",
      confirmButtonColor: "#e67e22",
      cancelButtonColor: "#666",
    });
    if (!confirm.isConfirmed) return;

    try {
      if (buttonEl) {
        buttonEl.disabled = true;
        buttonEl.innerHTML =
          '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span><span style="margin-right:8px">جاري التنفيذ...</span>';
      }

      const response = await fetch(`/api/forms/${encodeURIComponent(link)}/reset-users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usernames }),
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.success === false) {
        throw new Error(data.message || "تعذر إعادة تعيين المستخدم");
      }

      await Swal.fire({
        title: "تم",
        text: `تمت إعادة التعيين. عدد المحاولات المحذوفة: ${data.removed ?? 0}`,
        icon: "success",
        confirmButtonText: "حسنًا",
        confirmButtonColor: "#2ecc71",
      });

      loadForms();
    } catch (err) {
      await Swal.fire({
        title: "خطأ",
        text: err.message || "حدث خطأ",
        icon: "error",
        confirmButtonText: "حسنًا",
        confirmButtonColor: "#e74c3c",
      });
    } finally {
      if (buttonEl) {
        buttonEl.disabled = false;
        buttonEl.innerHTML = '<i class="fas fa-user-clock"></i> إعادة المحاولة للمستخدم';
      }
    }
  };

  window.reactivateForm = async function (formLink, buttonEl) {
    const { value: newExpiry } = await Swal.fire({
      title: "إعادة تفعيل النموذج",
      html: `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; width: 100%;">
          <p style="margin-bottom: 20px; font-weight: 600; color: var(--text); text-align: center;">
            اختر تاريخ ووقت انتهاء جديد للنموذج.
          </p>
          <input 
            id="newExpiry" 
            type="datetime-local" 
            class="swal2-input" 
            style="
              width: 90%; 
              max-width: 300px;
              margin: 10px auto; 
              display: block;
              background: rgba(0,0,0,0.2); 
              color: white; 
              border: 1px solid var(--border); 
              text-align: center;
              padding: 12px;
              border-radius: 8px;
            " 
            required
          >
          <small style="display: block; margin-top: 15px; color: var(--muted); text-align: center; line-height: 1.6;">
            سيتم نشر النموذج مرة أخرى فور الحفظ.
          </small>
        </div>
      `,
      showCancelButton: true,
      confirmButtonText: "حفظ وإعادة التفعيل",
      cancelButtonText: "إلغاء",
      confirmButtonColor: "#27ae60",
      cancelButtonColor: "#666",
      width: '500px',
      didOpen: () => {
        const input = document.getElementById("newExpiry");
        const now = new Date();
        now.setHours(now.getHours() + 24);
        const localIsoString = new Date(now.getTime() - (now.getTimezoneOffset() * 60000)).toISOString().slice(0, 16);
        input.value = localIsoString;
      },
      preConfirm: () => {
        const expiry = document.getElementById("newExpiry").value;
        if (!expiry) {
          Swal.showValidationMessage("يرجى إدخال تاريخ انتهاء صالح");
          return false;
        }
        return expiry;
      }
    });

    if (!newExpiry) return;

    try {
      if (buttonEl) {
        buttonEl.disabled = true;
        buttonEl.innerHTML =
          '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span><span style="margin-right:8px">جاري إعادة التفعيل...</span>';
      }

      const response = await fetch(`/api/forms/${formLink}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expiry: newExpiry }),
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok && data.success !== false) {
        await Swal.fire({
          title: "تم إعادة التفعيل",
          text: "تم إعادة تفعيل النموذج وتحديث تاريخ الانتهاء.",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadForms();
      } else {
        throw new Error(
          data.message || "فشل إعادة تفعيل النموذج، يرجى المحاولة مرة أخرى."
        );
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر إعادة تفعيل النموذج",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    } finally {
      if (buttonEl) {
        buttonEl.disabled = false;
        buttonEl.innerHTML = '<i class="fas fa-redo"></i> إعادة تفعيل';
      }
    }
  };

  window.copyFormLink = function (formLink) {
    const baseUrl = window.location.origin;
    const fullLink = `${baseUrl}/form/${formLink}`;
    navigator.clipboard
      .writeText(fullLink)
      .then(() => {
        Swal.fire({
          title: "تم النسخ!",
          text: "تم نسخ رابط النموذج بنجاح",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
      })
      .catch((error) => {
        Swal.fire({
          title: "خطأ!",
          text: "تعذر نسخ الرابط",
          icon: "error",
          confirmButtonText: "حسناً",
        });
      });
  };

  window.deactivateForm = async function deactivateForm(formLink, buttonEl) {
    const link = typeof formLink === "string" ? formLink.trim() : "";
    if (!link) {
      await Swal.fire({ title: "خطأ", text: "معرّف النموذج غير متوفر.", icon: "error", confirmButtonText: "حسنًا" });
      return;
    }
    const result = await Swal.fire({
      title: 'تعطيل النموذج',
      text: 'هل أنت متأكد أنك تريد تعطيل هذا النموذج؟ سيتم تعطيله وتحديد تاريخ انتهائه إلى تاريخ سابق.',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'نعم، عطل النموذج',
      cancelButtonText: 'إلغاء',
      confirmButtonColor: '#f39c12',
      cancelButtonColor: '#666',
    });

    if (!result.isConfirmed) return;

    try {
      if (buttonEl && typeof setButtonLoading === "function") {
        setButtonLoading(buttonEl, true, "جاري التعطيل...");
      } else if (buttonEl) {
        buttonEl.disabled = true;
        buttonEl.innerHTML =
          '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span><span style="margin-right:8px">جاري التعطيل...</span>';
      }

      const response = await fetch(
        `/api/forms/${encodeURIComponent(link)}/deactivate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
        }
      );

      const responseData = await response.json();

      if (response.ok) {
        await Swal.fire({
          title: "تم التعطيل",
          text:
            responseData.message ||
            "تم تعطيل النموذج بنجاح. سيتم تحديث الصفحة تلقائيًا.",
          icon: "success",
          confirmButtonText: "حسنًا",
          confirmButtonColor: "#2ecc71",
          timer: 2000,
          timerProgressBar: true,
          willClose: () => {
            window.location.reload();
          },
        });
      } else {
        throw new Error(responseData.message || "فشل تعطيل النموذج");
      }
    } catch (error) {
      console.error("Error deactivating form:", error);
      await Swal.fire({
        title: "خطأ",
        text:
          error.message ||
          "حدث خطأ أثناء محاولة تعطيل النموذج. يرجى المحاولة مرة أخرى لاحقًا.",
        icon: "error",
        confirmButtonText: "حسنًا",
        confirmButtonColor: "#e74c3c",
      });
    } finally {
      if (buttonEl && typeof setButtonLoading === "function") {
        setButtonLoading(buttonEl, false);
      } else if (buttonEl) {
        buttonEl.disabled = false;
        buttonEl.innerHTML = '<i class="fas fa-eye-slash"></i> تعطيل';
      }
    }
  }

  async function deleteFormFromList(formId, formLink, buttonEl) {
    const result = await Swal.fire({
      title: "هل أنت متأكد؟",
      text: "هل أنت متأكد أنك تريد حذف هذا النموذج نهائيًا؟ سيتم حذف جميع البيانات المرتبطة به ولا يمكن استرجاعها لاحقًا.",
      icon: "warning",
      showCancelButton: true,
      confirmButtonText: "نعم، احذف نهائيًا",
      cancelButtonText: "إلغاء",
      confirmButtonColor: "#e74c3c",
      cancelButtonColor: "#666",
    });

    if (result.isConfirmed) {
      try {
        if (buttonEl) {
          buttonEl.disabled = true;
          buttonEl.innerHTML =
            '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span><span style="margin-right:8px">جاري الحذف...</span>';
        }

        const deleteResponse = await fetch(`/api/forms/${formLink}`, {
          method: "DELETE",
          headers: {
            "Content-Type": "application/json",
          },
        });

        const responseData = await deleteResponse.json();

        if (deleteResponse.ok) {
          Swal.fire({
            title: "تم الحذف",
            text: responseData.message || "تم حذف النموذج نهائيًا بنجاح.",
            icon: "success",
            confirmButtonText: "حسنًا",
            confirmButtonColor: "#ffcc00",
          });
          loadForms();
        } else {
          throw new Error(responseData.message || "حدث خطأ أثناء حذف النموذج");
        }
      } catch (error) {
        console.error("Error deleting form:", error);
        Swal.fire({
          title: "خطأ",
          text:
            error.message ||
            "حدث خطأ أثناء محاولة حذف النموذج. يرجى المحاولة مرة أخرى لاحقًا.",
          icon: "error",
          confirmButtonText: "حسنًا",
        });
      } finally {
        if (buttonEl) {
          buttonEl.disabled = false;
          buttonEl.innerHTML = '<i class="fas fa-trash"></i> حذف';
        }
      }
    }
  }

  async function hydrateUserMenu() {
    try {
      const response = await fetch("/api/user-info", {
        credentials: "include",
      });
      const data = await response.json();
      if (!data.isAuthenticated) {
        window.location.href = "/login";
        return;
      }
      if (usernameDisplay) {
        usernameDisplay.textContent = data.username;
      }
      if (userRolePill) {
        userRolePill.textContent =
          data.role === "leadadmin"
            ? "ليد أدمن"
            : data.role === "admin"
              ? "أدمن"
              : data.role;
        userRolePill.className = "role-badge role-" + (data.role || "admin");
      }
      if (userMenuName) {
        userMenuName.textContent = data.username;
      }
      if (userMenuRole) {
        const roleMap = {
          leadadmin: "القائد العام",
          admin: "مسؤول النظام",
          teacher: "قائد صف",
          student: "طالب",
        };
        userMenuRole.textContent = roleMap[data.role] || data.role;
      }
      document.querySelectorAll("[data-nav-access]").forEach(function (el) {
        const key = el.getAttribute("data-nav-access");
        el.style.display = data[key] ? "" : "none";
      });
      return data;
    } catch (error) {
      console.error("Error fetching user info:", error);
      throw error;
    }
  }

  hydrateUserMenu()
    .then(() => {
      if (formsList) {
        loadForms();
      }
    })
    .catch((error) => {
      console.error("Error in hydrateUserMenu:", error);
      if (formsList) {
        loadForms();
      }
    });

  window.toggleMenu = function toggleMenu() {
    if (!userMenu) return;
    userMenu.style.display =
      userMenu.style.display === "block" ? "none" : "block";
  };

  async function performLogout() {
    const result = await Swal.fire({
      title: "تسجيل الخروج",
      text: "هل تريد فعلاً تسجيل الخروج من النظام؟",
      icon: "question",
      iconColor: "#ffcc00",
      showCancelButton: true,
      confirmButtonText: "نعم، تسجيل خروج",
      cancelButtonText: "إلغاء",
      confirmButtonColor: "#e74c3c",
      cancelButtonColor: "#666",
      background: "#2a1b3c",
      color: "#fff",
      backdrop: "rgba(0,0,0,0.8)",
      allowOutsideClick: false,
    });

    if (result.isConfirmed) {
      try {
        const response = await fetch("/logout", { method: "POST" });
        if (response.ok) {
          await Swal.fire({
            title: "تم تسجيل الخروج",
            text: "وداعاً! تم تسجيل خروجك بنجاح",
            icon: "success",
            iconColor: "#27ae60",
            background: "#2a1b3c",
            color: "#fff",
            backdrop: "rgba(0,0,0,0.8)",
            showConfirmButton: false,
            timer: 1500,
          });
          setTimeout(() => {
            window.location.href = "/";
          }, 500);
        }
      } catch (error) {
        console.error("Logout error:", error);
        window.location.href = "/";
      }
    }
  }

  if (logoutButton) {
    logoutButton.addEventListener("click", performLogout);
  }

  if (logoutBtnMobile) {
    logoutBtnMobile.addEventListener("click", performLogout);
  }

  document.addEventListener("click", (event) => {
    if (!userMenu) return;
    const userDisplay = document.querySelector(".user-display");
    if (
      userMenu.contains(event.target) ||
      (userDisplay && userDisplay.contains(event.target))
    ) {
      return;
    }
    userMenu.style.display = "none";
  });
});

if (typeof window !== "undefined" && typeof window.deactivateForm === "undefined") {
  window.deactivateForm = function (formLink, buttonEl) {
    console.warn("deactivateForm called before initialization", formLink);
  };
}
