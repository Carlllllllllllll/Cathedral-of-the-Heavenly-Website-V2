const mobileToggle = document.getElementById("mobileToggle");
const sidebar = document.getElementById("sidebar");
const logoutBtn = document.getElementById("logoutBtn");
const logoutBtnMobile = document.getElementById("logoutBtnMobile");
const usersList = document.getElementById("usersList");
const bannedUsersList = document.getElementById("bannedUsersList");
const toggleViewBtn = document.getElementById("toggleViewBtn");
const refreshUsersBtn = document.getElementById("refreshUsersBtn");
const searchInput = document.getElementById("searchInput");
const clearSearch = document.getElementById("clearSearch");
const usersSection = document.getElementById("usersSection");
const bannedSection = document.getElementById("bannedSection");
const takePointsModal = document.getElementById("takePointsModal");
const takePointsForm = document.getElementById("takePointsForm");
const banModal = document.getElementById("banModal");
const banForm = document.getElementById("banForm");
const editUserModal = document.getElementById("editUserModal");
const editUserForm = document.getElementById("editUserForm");
const categoryNav = document.getElementById("categoryNav");
const categoryTabs = document.querySelectorAll(".category-tab");
const gradesToggle = document.getElementById("gradesToggle");
const gradesSubmenu = document.getElementById("gradesSubmenu");
const sectionToggles = document.querySelectorAll(".section-toggle");
const closeEditModal = document.getElementById("closeEditModal");
const cancelEditModal = document.getElementById("cancelEditModal");
const closeTakePointsModalBtn = document.getElementById(
  "closeTakePointsModalBtn",
);
const cancelTakePointsModal = document.getElementById("cancelTakePointsModal");
const closeBanModalBtn = document.getElementById("closeBanModal");
const cancelBanModal = document.getElementById("cancelBanModal");
const categoryDropdown = document.getElementById("categoryDropdown");
const categoryToggle = document.getElementById("categoryToggle");
const dropdownMenu = document.getElementById("dropdownMenu");
const categoryOptions = document.querySelectorAll(".category-option");
const suggestionsToggle = document.getElementById("suggestionsToggle");
const suggestionsSubmenu = document.getElementById("suggestionsSubmenu");

let allUsers = [];
let allBannedUsers = [];
let currentCategory = "all";
let currentSearch = "";
let currentAdminUsername = null;
let serverCounts = null;
let userCounts = {
  all: 0,
  sec1: 0,
  sec2: 0,
  sec3: 0,
  prep1: 0,
  prep2: 0,
  prep3: 0,
  teachers: 0,
  admins: 0,
};

function toggleSidebar(e) {
  if (e) e.preventDefault();
  if (e) e.stopPropagation();
  if (!sidebar || !mobileToggle) return;
  sidebar.classList.toggle("active");
  const spans = mobileToggle.querySelectorAll("span");
  if (sidebar.classList.contains("active")) {
    spans[0].style.transform = "rotate(45deg) translate(5px, 5px)";
    spans[1].style.opacity = "0";
    spans[2].style.transform = "rotate(-45deg) translate(7px, -6px)";
  } else {
    spans[0].style.transform = "none";
    spans[1].style.opacity = "1";
    spans[2].style.transform = "none";
  }
}

if (mobileToggle && sidebar) {
  mobileToggle.addEventListener("click", toggleSidebar);
  mobileToggle.addEventListener("touchstart", toggleSidebar);
}

if (gradesToggle) {
  gradesToggle.addEventListener("click", function (e) {
    e.stopPropagation();
    e.preventDefault();
    this.classList.toggle("active");
    const icon = this.querySelector(".toggle-icon");
    if (this.classList.contains("active")) {
      icon.classList.remove("fa-chevron-down");
      icon.classList.add("fa-chevron-up");
      if (gradesSubmenu) {
        gradesSubmenu.style.maxHeight =
          Math.min(gradesSubmenu.scrollHeight, 400) + "px";
      }
    } else {
      icon.classList.remove("fa-chevron-up");
      icon.classList.add("fa-chevron-down");
      if (gradesSubmenu) gradesSubmenu.style.maxHeight = "0";
      document.querySelectorAll(".section-toggle.active").forEach((toggle) => {
        toggle.classList.remove("active");
        const subIcon = toggle.querySelector(".toggle-icon");
        if (subIcon) {
          subIcon.classList.remove("fa-chevron-up");
          subIcon.classList.add("fa-chevron-down");
        }
        const sectionSub = document.querySelector(
          `.section-submenu[data-section="${toggle.dataset.section}"]`,
        );
        if (sectionSub) sectionSub.style.maxHeight = "0";
      });
    }
  });
}

if (gradesSubmenu) {
  gradesSubmenu.style.maxHeight = "0";
}

if (suggestionsSubmenu) {
  suggestionsSubmenu.style.maxHeight = "0";
}

document.querySelectorAll(".section-submenu").forEach((submenu) => {
  submenu.style.maxHeight = "0";
});

sectionToggles.forEach((toggle) => {
  toggle.addEventListener("click", function (e) {
    e.stopPropagation();
    e.preventDefault();
    this.classList.toggle("active");
    const icon = this.querySelector(".toggle-icon");
    const sectionSub = document.querySelector(
      `.section-submenu[data-section="${this.dataset.section}"]`,
    );
    if (!sectionSub) return;

    if (this.classList.contains("active")) {
      if (icon) {
        icon.classList.remove("fa-chevron-down");
        icon.classList.add("fa-chevron-up");
      }
      sectionSub.style.maxHeight = sectionSub.scrollHeight + "px";
    } else {
      if (icon) {
        icon.classList.remove("fa-chevron-up");
        icon.classList.add("fa-chevron-down");
      }
      sectionSub.style.maxHeight = "0";
    }
  });
});

if (suggestionsToggle) {
  suggestionsToggle.addEventListener("click", function (e) {
    e.stopPropagation();
    e.preventDefault();
    this.classList.toggle("active");
    const icon = this.querySelector(".toggle-icon");

    if (this.classList.contains("active")) {
      if (icon) {
        icon.classList.remove("fa-chevron-down");
        icon.classList.add("fa-chevron-up");
      }
      if (suggestionsSubmenu) {
        suggestionsSubmenu.style.maxHeight =
          Math.min(suggestionsSubmenu.scrollHeight, 300) + "px";
      }
    } else {
      if (icon) {
        icon.classList.remove("fa-chevron-up");
        icon.classList.add("fa-chevron-down");
      }
      if (suggestionsSubmenu) suggestionsSubmenu.style.maxHeight = "0";
    }
  });
}

async function loadUserInfo() {
  try {
    const response = await fetch("/api/user-info", { credentials: "include" });
    if (response.status === 401) {
      window.location.href =
        "/login?redirect=" +
        encodeURIComponent(window.location.pathname + window.location.search);
      return;
    }
    const data = await response.json().catch(() => ({}));
    if (!data.isAuthenticated) {
      window.location.href =
        "/login?redirect=" +
        encodeURIComponent(window.location.pathname + window.location.search);
      return;
    }
    currentAdminUsername = data.username;
    const usernameEl = document.getElementById("username");
    if (usernameEl) usernameEl.textContent = data.username;
    const roleEl = document.getElementById("userRole");
    if (roleEl) {
      roleEl.textContent =
        data.role === "leadadmin"
          ? "ليد أدمن"
          : data.role === "admin"
            ? "مشرف"
            : data.role;
      roleEl.className = "role-badge role-" + (data.role || "admin");
    }
    document.querySelectorAll("[data-nav-access]").forEach(function (el) {
      var key = el.getAttribute("data-nav-access");
      el.style.display = data[key] ? "" : "none";
    });
  } catch (error) {
    console.error("Error loading user info:", error);
  }
}

function updateCategoryCounts() {
  if (serverCounts && typeof serverCounts === "object") {
    userCounts = {
      all: Number(serverCounts.all) || 0,
      sec1: Number(serverCounts.sec1) || 0,
      sec2: Number(serverCounts.sec2) || 0,
      sec3: Number(serverCounts.sec3) || 0,
      prep1: Number(serverCounts.prep1) || 0,
      prep2: Number(serverCounts.prep2) || 0,
      prep3: Number(serverCounts.prep3) || 0,
      teachers: Number(serverCounts.teachers) || 0,
      admins: Number(serverCounts.admins) || 0,
    };
  } else {
    userCounts = {
      all: allUsers.length,
      sec1: allUsers.filter((user) => user.grade === "sec1").length,
      sec2: allUsers.filter((user) => user.grade === "sec2").length,
      sec3: allUsers.filter((user) => user.grade === "sec3").length,
      prep1: allUsers.filter((user) => user.grade === "prep1").length,
      prep2: allUsers.filter((user) => user.grade === "prep2").length,
      prep3: allUsers.filter((user) => user.grade === "prep3").length,
      teachers: allUsers.filter((user) => user.grade === "teachers").length,
      admins: allUsers.filter((user) => user.grade === "admins").length,
    };
  }

  for (const category in userCounts) {
    const countElement = document.getElementById(`count-${category}`);
    if (countElement) {
      countElement.textContent = userCounts[category];
    }
  }
}

const INITIAL_PAGE_SIZE = 4;
const LOAD_MORE_SIZE = 2;
let totalActiveUsers = 0;
let loadingMore = false;
let usersListObserver = null;
let usersListScrollFallbackBound = false;
let usersScrollCheckFn = null;

async function loadUsers(reset) {
  if (reset !== false && usersList) {
    usersList.innerHTML = `
          <div class="loading-state">
              <span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span>
              <p>جاري تحميل المستخدمين...</p>
          </div>
      `;
  }
  try {
    const params = new URLSearchParams({ limit: INITIAL_PAGE_SIZE, skip: 0 });
    if (currentCategory && currentCategory !== "all")
      params.set("grade", currentCategory);
    if (currentSearch) params.set("search", currentSearch);
    const response = await fetch("/api/admin/users?" + params.toString(), {
      credentials: "include",
    });
    if (response.status === 401) {
      window.location.href =
        "/login?redirect=" +
        encodeURIComponent(window.location.pathname + window.location.search);
      return;
    }
    if (!response.ok) throw new Error("HTTP error! status: " + response.status);
    const data = await response.json().catch(() => ({}));
    const activeUsers =
      data.users && Array.isArray(data.users) ? data.users : [];
    totalActiveUsers = data.total != null ? data.total : activeUsers.length;
    serverCounts =
      data.counts && typeof data.counts === "object" ? data.counts : null;
    allUsers = activeUsers;

    const bannedResponse = await fetch("/api/banned-users", {
      credentials: "include",
    });
    if (bannedResponse.status === 401) {
      window.location.href =
        "/login?redirect=" +
        encodeURIComponent(window.location.pathname + window.location.search);
      return;
    }
    const bannedUsers = await bannedResponse.json().catch(() => []);
    allBannedUsers = Array.isArray(bannedUsers) ? bannedUsers : [];

    const statsEl = document.getElementById("dashboard-stats");
    if (statsEl) {
      statsEl.innerHTML = `
              <div class="stat-card stat-success">
                <div class="stat-icon"><i class="fas fa-user-check"></i></div>
                <div class="stat-value">${totalActiveUsers}</div>
                <div class="stat-label">مستخدمون نشطون</div>
              </div>
              <div class="stat-card stat-danger">
                <div class="stat-icon"><i class="fas fa-user-slash"></i></div>
                <div class="stat-value">${allBannedUsers.length}</div>
                <div class="stat-label">محظورون</div>
              </div>
              <div class="stat-card stat-info">
                <div class="stat-icon"><i class="fas fa-users"></i></div>
                <div class="stat-value">${totalActiveUsers + allBannedUsers.length}</div>
                <div class="stat-label">الإجمالي</div>
              </div>
            `;
    }

    if (activeUsers.length === 0) {
      if (usersList) {
        usersList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-users-slash"></i>
                    <h3>لا يوجد مستخدمون نشطون</h3>
                    <p>لا يوجد مستخدمون نشطون في النظام</p>
                </div>
            `;
      }
      updateCategoryCounts();
      return;
    }
    updateCategoryCounts();
    displayUsers(allUsers);
    maybeAppendScrollSentinel();
    await autoFillUsersToEnableScroll();
  } catch (error) {
    console.error("Error loading users:", error);
    if (usersList) {
      usersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-circle"></i>
                <h3>حدث خطأ</h3>
                <p>تعذر تحميل بيانات المستخدمين. يرجى المحاولة مرة أخرى.</p>
            </div>
        `;
    }
  }
}

async function loadMoreUsers() {
  if (loadingMore || allUsers.length >= totalActiveUsers) return;
  loadingMore = true;
  const sentinel = document.getElementById("users-list-sentinel");
  if (sentinel) {
    sentinel.classList.add("loading");
    sentinel.innerHTML = `<div class="users-loading-indicator">
      <span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span>
      <span class="users-loading-text">جاري التحميل...</span>
    </div>`;
  }
  try {
    const params = new URLSearchParams({
      limit: LOAD_MORE_SIZE,
      skip: allUsers.length,
    });
    if (currentCategory && currentCategory !== "all")
      params.set("grade", currentCategory);
    if (currentSearch) params.set("search", currentSearch);
    const response = await fetch("/api/admin/users?" + params.toString(), {
      credentials: "include",
    });
    if (response.status === 401) {
      window.location.href =
        "/login?redirect=" +
        encodeURIComponent(window.location.pathname + window.location.search);
      return;
    }
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json().catch(() => ({}));
    const nextUsers = data.users && Array.isArray(data.users) ? data.users : [];
    if (data.total != null) totalActiveUsers = data.total;
    if (data.counts && typeof data.counts === "object")
      serverCounts = data.counts;
    if (nextUsers.length === 0) {
      loadingMore = false;
      if (sentinel) {
        sentinel.classList.remove("loading");
        sentinel.innerHTML = "";
      }
      return;
    }
    const existingIds = new Set(
      allUsers.map((u) => (u && u._id ? String(u._id) : "")),
    );
    const uniqueNext = nextUsers.filter((u) => {
      const id = u && u._id ? String(u._id) : "";
      if (!id) return true;
      if (existingIds.has(id)) return false;
      existingIds.add(id);
      return true;
    });
    allUsers = allUsers.concat(uniqueNext);
    const newCardsHtml = getUsersCardsHtml(uniqueNext);
    if (sentinel) sentinel.insertAdjacentHTML("beforebegin", newCardsHtml);
    updateCategoryCounts();

    if (sentinel && allUsers.length >= totalActiveUsers) {
      sentinel.remove();
    }
  } catch (e) {
    console.error("Load more error:", e);
  } finally {
    loadingMore = false;
    if (sentinel) {
      sentinel.classList.remove("loading");
      sentinel.innerHTML = "";
    }
  }
}

function maybeAppendScrollSentinel() {
  if (!usersList) return;
  if (allUsers.length >= totalActiveUsers) {
    document.getElementById("users-list-sentinel")?.remove();
    return;
  }

  const existing = document.getElementById("users-list-sentinel");
  if (existing) {
    if (usersListObserver) usersListObserver.observe(existing);
    bindUsersScrollFallback();
    return;
  }
  const sentinel = document.createElement("div");
  sentinel.id = "users-list-sentinel";
  sentinel.className = "users-list-sentinel";
  sentinel.setAttribute("aria-hidden", "true");
  usersList.appendChild(sentinel);

  if (typeof IntersectionObserver === "function") {
    if (!usersListObserver) {
      usersListObserver = new IntersectionObserver(
        (entries) => {
          if (entries && entries[0] && entries[0].isIntersecting)
            loadMoreUsers();
        },
        { root: null, rootMargin: "400px", threshold: 0 },
      );
    }
    usersListObserver.observe(sentinel);
  }

  bindUsersScrollFallback();
}

function bindUsersScrollFallback() {
  if (usersListScrollFallbackBound) return;
  usersListScrollFallbackBound = true;

  const onScroll = () => {
    if (loadingMore) return;
    if (allUsers.length >= totalActiveUsers) return;
    const doc = document.documentElement;
    const scrollBottom =
      (window.scrollY || doc.scrollTop || 0) + window.innerHeight;
    const docHeight = doc.scrollHeight || 0;
    if (docHeight > 0 && scrollBottom >= docHeight - 800) {
      loadMoreUsers();
    }
  };

  usersScrollCheckFn = onScroll;

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") onScroll();
  });

  setTimeout(onScroll, 0);
}

async function autoFillUsersToEnableScroll() {
  if (loadingMore) return;
  if (allUsers.length >= totalActiveUsers) return;

  const maxRounds = 20;
  for (let i = 0; i < maxRounds; i++) {
    const doc = document.documentElement;
    const docHeight = doc.scrollHeight || 0;
    const viewport = window.innerHeight || 0;
    const canScroll = docHeight > viewport + 50;
    if (canScroll) break;
    if (allUsers.length >= totalActiveUsers) break;
    await loadMoreUsers();
  }

  if (typeof usersScrollCheckFn === "function") {
    usersScrollCheckFn();
  }
}

function displayUsersByCategory(category) {
  let filteredUsers = allUsers;

  if (category !== "all") {
    filteredUsers = allUsers.filter((user) => user.grade === category);
  }

  if (filteredUsers.length === 0) {
    if (usersList) {
      usersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-users-slash"></i>
                <h3>لا يوجد مستخدمون</h3>
                <p>لا يوجد مستخدمون في هذه الفئة</p>
            </div>
        `;
    }
  } else {
    displayUsers(filteredUsers);
  }
}

function getUsersCardsHtml(users) {
  return (users || [])
    .map((user) => {
      const firstName =
        user && user.firstName != null ? String(user.firstName).trim() : "";
      const secondName =
        user && user.secondName != null ? String(user.secondName).trim() : "";
      const safeUsername =
        user && user.username != null ? String(user.username).trim() : "";
      const fullNameSafe =
        `${firstName} ${secondName}`.trim() || safeUsername || "غير متوفر";

      const gradeText =
        {
          prep1: "أولى إعدادي",
          prep2: "ثانية إعدادي",
          prep3: "ثالثة إعدادي",
          sec1: "أولى ثانوي",
          sec2: "ثانية ثانوي",
          sec3: "ثالثة ثانوي",
          teachers: "خادم",
          admins: "مشرف",
        }[user.grade] || user.grade;
      const pointsVal = user.points != null ? user.points : 0;
      const pointsDisplay =
        pointsVal < 0 ? `\u2212${Math.abs(pointsVal)}` : pointsVal;

      const roleText =
        {
          leadadmin: "ليد أدمن",
          admin: "مشرف",
          teacher: "خادم",
          student: "طالب",
        }[user.role] || user.role;

      const userStatus = getUserStatus(user);
      const statusBadge = getStatusBadge(userStatus);

      const verificationBadge = user.verificationCodeVerified
        ? '<span class="status-badge verified-badge">✅ تم التحقق</span>'
        : '<span class="status-badge not-verified-badge">❌ غير متحقق</span>';

      const lastActivityText = user.lastActivity
        ? `آخر نشاط: ${formatTimeAgo(new Date(user.lastActivity))}`
        : "لم يتم تسجيل نشاط بعد";

      const logoutAllDevicesBtn =
        user.role !== "leadadmin"
          ? `
                    <button class="action-btn logout-all-btn" onclick="logoutAllDevices('${user._id}', '${user.username}')">
                        <i class="fas fa-sign-out-alt"></i>
                        تسجيل الخروج من جميع الأجهزة
                    </button>
                    `
          : "";

      return `
                <div class="user-card ${user._isLocal === true ? "is-local-user" : ""}">
                    <div class="user-card-header">
                        <div class="user-avatar-large ${
                          userStatus === "banned" ? "banned-avatar" : ""
                        }">
                            <i class="fas fa-user-circle"></i>
                        </div>
                        <div class="user-main-info">
                            <h3>${fullNameSafe}</h3>
                            <div class="user-badges">
                                <span class="username-badge">@${
                                  safeUsername
                                }</span>
                                <span class="role-badge ${
                                  user.role
                                }">${roleText}</span>
                                <span class="grade-badge">${gradeText}</span>
                                ${statusBadge}
                                ${verificationBadge}
                            </div>
                            <div class="user-status-info">
                                <small class="last-login-text">${lastActivityText}</small>
                            </div>
                        </div>
                        <div class="user-points">
                            <i class="fas fa-star"></i>
                            <span dir="ltr">${pointsDisplay}</span>
                        </div>
                    </div>
                    
                    <div class="user-card-details">
                        <div class="detail-row">
                            <span class="detail-label">البريد الإلكتروني:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${user.email || "غير متوفر"}</span>
                              <button class="copy-btn" type="button" title="نسخ البريد" onclick="copyText('${(
                                user.email || ""
                              ).replace(/'/g, "\\'")}')">
                                <i class="fas fa-copy"></i>
                              </button>
                            </span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">رقم الهاتف:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${user.phone || "غير متوفر"}</span>
                              <button class="copy-btn" type="button" title="نسخ رقم الهاتف" onclick="copyText('${(
                                user.phone || ""
                              ).replace(/'/g, "\\'")}')">
                                <i class="fas fa-copy"></i>
                              </button>
                            </span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">تاريخ التسجيل:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${new Date(
                                user.createdAt,
                              ).toLocaleDateString("ar-EG")}</span>
                            </span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">آخر نشاط:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${
                                user.lastActivity
                                  ? new Date(user.lastActivity).toLocaleString(
                                      "ar-EG",
                                    )
                                  : "لم يتم تسجيل نشاط بعد"
                              }</span>
                            </span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">حالة الحساب:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${getStatusDescription(
                                userStatus,
                              )}</span>
                            </span>
                        </div>
                        ${
                          user._isLocal === true
                            ? `
                        <div class="detail-row local-user-row">
                            <span class="detail-label">
                              <i class="fas fa-database"></i>
                              مستخدم محلي
                            </span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">
                                هذا المستخدم مخزَّن محليًا ولا يمكن تعديله من خلال لوحة الإدارة
                              </span>
                            </span>
                        </div>
                        `
                            : ""
                        }
                        ${
                          user.verificationCodeVerified
                            ? `
                        <div class="detail-row verified-status-row" style="background: rgba(46, 204, 113, 0.1); border: 1px solid rgba(46, 204, 113, 0.3); border-radius: 8px;">
                            <span class="detail-label" style="color: #2ecc71; font-weight: 700;">حالة التحقق من الحساب:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value" style="color: #2ecc71; font-weight: 700; font-size: 14px;">✅ تم التحقق</span>
                            </span>
                        </div>
                        `
                            : user.verificationCode
                              ? `
                        <div class="detail-row verified-status-row" style="background: rgba(255, 204, 0, 0.1); border: 1px solid rgba(255, 204, 0, 0.3); border-radius: 8px;">
                            <span class="detail-label" style="color: #ffcc00; font-weight: 700;">🔑 كود التحقق:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value" style="color: #ffcc00; font-weight: 700; font-size: 16px; font-family: monospace;">${
                                user.verificationCode
                              }</span>
                              <button class="copy-btn" type="button" title="نسخ كود التحقق" onclick="copyText('${user.verificationCode.replace(
                                /'/g,
                                "\\'",
                              )}')">
                                <i class="fas fa-copy"></i>
                              </button>
                            </span>
                        </div>
                        `
                              : ""
                        }
                    </div>
                    
                    <div class="user-card-footer">
                    <div class="user-card-actions">
                        <button class="action-btn points-btn" onclick="givePoints('${
                          user._id
                        }', '${user.username}')">
                            <i class="fas fa-plus-circle"></i>
                            إضافة نقاط
                        </button>
                        <button class="action-btn remove-points-btn" onclick="openTakePointsModal('${
                          user._id
                        }', '${user.username}')">
                            <i class="fas fa-minus-circle"></i>
                            خصم نقاط
                        </button>
                        <button class="action-btn edit-btn" onclick="openEditUserModal('${
                          user._id
                        }')">
                            <i class="fas fa-edit"></i>
                            تعديل
                        </button>
                        <button class="action-btn reset-link-btn" onclick="generatePasswordResetLink('${
                          user._id
                        }', '${(user.username || "").replace(/'/g, "\\'")}')" title="إنشاء رابط تغيير كلمة المرور (7 أيام)">
                            <i class="fas fa-key"></i>
                            رابط كلمة المرور
                        </button>
                        <button class="action-btn reset-links-view-btn" onclick="showPasswordResetLinks('${
                          user._id
                        }', '${(user.username || "").replace(/'/g, "\\'")}')" title="عرض الرابط الحالية والسابقة">
                            <i class="fas fa-link"></i>
                            عرض الرابط
                        </button>
                        <button class="action-btn ban-btn" onclick="openBanModal('${
                          user._id
                        }', '${user.username}')">
                            <i class="fas fa-ban"></i>
                            حظر
                        </button>
                        <button class="action-btn delete-btn" onclick="deleteUser('${
                          user._id
                        }', '${user.username}')">
                            <i class="fas fa-trash"></i>
                            حذف
                        </button>
                        ${logoutAllDevicesBtn}
                    </div>
                    </div>
                </div>
            `;
    })
    .join("");
}

function displayUsers(users) {
  if (usersList) usersList.innerHTML = getUsersCardsHtml(users || []);
  maybeAppendScrollSentinel();
}
async function logoutAllDevices(userId, username) {
  const result = await Swal.fire({
    title: "تسجيل الخروج من جميع الأجهزة",
    text: `هل أنت متأكد أنك تريد تسجيل خروج "${username}" من جميع الأجهزة؟`,
    icon: "question",
    showCancelButton: true,
    confirmButtonText: "نعم، تسجيل الخروج",
    cancelButtonText: "إلغاء",
    confirmButtonColor: "#3498db",
    cancelButtonColor: "#666",
  });

  if (result.isConfirmed) {
    Swal.fire({
      title: "جاري تسجيل الخروج...",
      text: "يرجى الانتظار جاري تسجيل الخروج من جميع الأجهزة",
      icon: "info",
      showConfirmButton: false,
      allowOutsideClick: false,
      didOpen: () => {
        Swal.showLoading();
      },
    });

    try {
      const response = await fetch(`/api/admin/users/${userId}/logout-all`, {
        method: "POST",
      });

      Swal.close();

      if (response.ok) {
        Swal.fire({
          title: "تم بنجاح!",
          text: "تم تسجيل خروج المستخدم من جميع الأجهزة",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
      } else {
        throw new Error("فشل تسجيل الخروج من جميع الأجهزة");
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر تسجيل الخروج من جميع الأجهزة",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    }
  }
}

async function generatePasswordResetLink(userId, username) {
  if (typeof window.ensureSessionValid === "function") {
    const ok = await window.ensureSessionValid();
    if (!ok) return;
  }
  const result = await Swal.fire({
    title: "رابط تغيير كلمة المرور",
    text: `إنشاء رابط جديد لتغيير كلمة مرور "${username}"؟ الرابط صالح 7 أيام وسيلغي أي رابط سابق.`,
    icon: "question",
    showCancelButton: true,
    confirmButtonText: "نعم، إنشاء الرابط",
    cancelButtonText: "إلغاء",
    confirmButtonColor: "#ffcc00",
    cancelButtonColor: "#666",
    background: "#2a1b3c",
    color: "#f2f4ff",
  });
  if (!result.isConfirmed) return;
  Swal.fire({
    title: "جاري الإنشاء...",
    text: "يرجى الانتظار",
    icon: "info",
    showConfirmButton: false,
    allowOutsideClick: false,
    didOpen: () => Swal.showLoading(),
    background: "#2a1b3c",
    color: "#f2f4ff",
  });
  try {
    const response = await fetch(
      `/api/admin/users/${userId}/password-reset-link`,
      { method: "POST" },
    );
    const data = await response.json().catch(() => ({}));
    Swal.close();
    if (response.ok && data.success && data.link) {
      await navigator.clipboard.writeText(data.link).catch(() => {});
      const expiresText = data.expiresAt
        ? new Date(data.expiresAt).toLocaleString("ar-EG")
        : "7 أيام";
      Swal.fire({
        title: "تم إنشاء الرابط",
        html: `
          <div class="reset-created-simple">
            <div class="reset-created-simple-meta">
              <span>صالح حتى:</span>
              <strong>${expiresText}</strong>
            </div>
            <div class="reset-created-simple-box">
              <button type="button" id="copyResetLinkBtn" class="reset-created-simple-copy" title="نسخ الرابط">
                <i class="fas fa-copy"></i>
              </button>
              <textarea readonly id="resetLinkTextarea" class="reset-created-simple-textarea">${data.link}</textarea>
            </div>
            <div class="reset-created-simple-note">لو محتاج كود التحقق، افتح <strong>عرض الرابط</strong> من لوحة المستخدم.</div>
            ${
              data.message
                ? `<div class="reset-created-simple-note">${String(data.message).replace(/</g, "&lt;")}</div>`
                : ""
            }
          </div>
        `,
        icon: "success",
        confirmButtonText: "حسناً",
        confirmButtonColor: "#ffcc00",
        width: "min(520px, 92vw)",
        background: "#2a1b3c",
        color: "#f2f4ff",
        didOpen: () => {
          document
            .getElementById("copyResetLinkBtn")
            ?.addEventListener("click", () => {
              navigator.clipboard.writeText(data.link).then(() => {
                Swal.fire({
                  title: "تم النسخ",
                  icon: "success",
                  timer: 1200,
                  showConfirmButton: false,
                  background: "#2a1b3c",
                  color: "#f2f4ff",
                });
              });
            });
        },
      });
    } else {
      throw new Error(data.message || "فشل إنشاء الرابط");
    }
  } catch (err) {
    Swal.fire({
      title: "خطأ",
      text: err.message || "تعذر إنشاء رابط تغيير كلمة المرور",
      icon: "error",
      confirmButtonText: "حسناً",
      confirmButtonColor: "#ffcc00",
      background: "#2a1b3c",
      color: "#f2f4ff",
    });
  }
}

async function showPasswordResetLinks(userId, username) {
  if (typeof window.ensureSessionValid === "function") {
    const ok = await window.ensureSessionValid();
    if (!ok) return;
  }
  Swal.fire({
    title: "جاري التحميل...",
    text: "عرض رابط تغيير كلمة المرور",
    icon: "info",
    showConfirmButton: false,
    allowOutsideClick: false,
    didOpen: () => Swal.showLoading(),
    background: "#2a1b3c",
    color: "#f2f4ff",
  });
  try {
    const response = await fetch(
      `/api/admin/users/${userId}/password-reset-links`,
    );
    const data = await response.json().catch(() => ({}));
    Swal.close();
    if (!response.ok) throw new Error(data.message || "فشل تحميل الروابط");
    const allLinks = data.links || [];
    const activeOnly = allLinks.filter((l) => l.active);
    const links = activeOnly.length > 0 ? activeOnly : allLinks;
    const formatDate = (d) => (d ? new Date(d).toLocaleString("ar-EG") : "—");
    const single = links && links.length ? links[0] : null;
    const emptyMessage =
      activeOnly.length === 0 && allLinks.length > 0
        ? "لا توجد روابط نشطة. جميع الروابط منتهية."
        : "لا توجد روابط مسجّلة";

    const buildSingleHtml = () => {
      if (!single) {
        return `<div class="reset-links-single-empty">${emptyMessage}</div>`;
      }

      const url = (single.url || "").toString();
      const urlSafeAttr = url.replace(/</g, "&lt;");
      const urlB64 = btoa(unescape(encodeURIComponent(url)));

      const code = (single.verificationCode || "").toString();
      const codeSafe = code.replace(/</g, "&lt;");
      const codeB64 = btoa(unescape(encodeURIComponent(code)));

      const statusText = single.active ? "نشط" : "منتهي";
      const verifiedText = single.verifiedAt ? "✅ تم" : "⏳ لم يتم";
      const createdBy = (single.createdBy || "—")
        .toString()
        .replace(/</g, "&lt;");

      return `<div class="reset-links-single">
        <div class="rl-single-top">
          <div class="rl-single-badges">
            <span class="rl-badge ${single.active ? "rl-badge-active" : "rl-badge-expired"}">${statusText}</span>
            <span class="rl-badge ${single.verifiedAt ? "rl-badge-verified" : "rl-badge-pending"}">${verifiedText}</span>
          </div>
        </div>

        <div class="rl-single-link">
          <div class="rl-single-link-label">الرابط</div>
          <div class="rl-single-link-box">
            <a class="rl-link-arrow" href="${urlSafeAttr}" target="_blank" rel="noopener noreferrer" title="فتح الرابط">
              <i class="fas fa-arrow-up-right-from-square"></i>
            </a>
            <textarea class="rl-link-text" readonly>${urlSafeAttr}</textarea>
            <button type="button" class="rl-icon-btn rl-link-copy links-copy-btn" data-url-b64="${urlB64}" title="نسخ الرابط">
              <i class="fas fa-copy"></i>
            </button>
          </div>
        </div>

        ${
          codeSafe
            ? `<div class="rl-single-code">
              <div class="rl-single-code-label">الكود</div>
              <div class="rl-single-code-box">
                <code class="rl-single-code-value">${codeSafe}</code>
                <button type="button" class="rl-icon-btn links-copy-code-btn" data-code-b64="${codeB64}" title="نسخ الكود">
                  <i class="fas fa-copy"></i>
                </button>
              </div>
            </div>`
            : ""
        }

        <div class="rl-single-footer" aria-hidden="true">
          <span>أنشئ: ${formatDate(single.createdAt)}</span>
          <span>ينتهي: ${formatDate(single.expiresAt)}</span>
          <span>بواسطة: ${createdBy}</span>
        </div>
      </div>`;
    };
    Swal.fire({
      title: `رابط تغيير كلمة المرور — ${username}`,
      html: buildSingleHtml(),
      icon: "info",
      customClass: { popup: "reset-links-swal" },
      confirmButtonText: "إغلاق",
      confirmButtonColor: "#ffcc00",
      width: "min(700px, 96vw)",
      heightAuto: false,
      scrollbarPadding: false,
      background: "#2a1b3c",
      color: "#f2f4ff",
      didOpen: () => {
        document.querySelectorAll(".links-copy-btn").forEach((btn) => {
          btn.addEventListener("click", () => {
            const b64 = btn.getAttribute("data-url-b64");
            const url = b64 ? decodeURIComponent(escape(atob(b64))) : "";
            copyText(url);
          });
        });
        document.querySelectorAll(".links-copy-code-btn").forEach((btn) => {
          btn.addEventListener("click", () => {
            const b64 = btn.getAttribute("data-code-b64");
            const code = b64 ? decodeURIComponent(escape(atob(b64))) : "";
            copyText(code);
          });
        });
        document.querySelectorAll(".rl-link-text").forEach((ta) => {
          ta.addEventListener("focus", () => {
            try {
              ta.select();
              ta.setSelectionRange(0, ta.value.length);
            } catch (_) {}
          });
          ta.addEventListener("click", () => {
            try {
              ta.select();
              ta.setSelectionRange(0, ta.value.length);
            } catch (_) {}
          });
        });
      },
    });
  } catch (err) {
    Swal.fire({
      title: "خطأ",
      text: err.message || "تعذر تحميل الروابط",
      icon: "error",
      confirmButtonText: "حسناً",
      confirmButtonColor: "#ffcc00",
      background: "#2a1b3c",
      color: "#f2f4ff",
    });
  }
}

function openEditUserModal(userId) {
  const user = allUsers.find((u) => u._id === userId);
  if (!user) return;

  if (user._isLocal === true) {
    Swal.fire({
      title: "غير مسموح!",
      text: "يرجى التواصل مع كارل لتعديل هذا المستخدم",
      icon: "warning",
      confirmButtonText: "حسناً",
      confirmButtonColor: "#ffcc00",
    });
    return;
  }

  const editUserId = document.getElementById("editUserId");
  const editFirstName = document.getElementById("editFirstName");
  const editSecondName = document.getElementById("editSecondName");
  const editEmail = document.getElementById("editEmail");
  const editPhone = document.getElementById("editPhone");
  const editGrade = document.getElementById("editGrade");
  const editPassword = document.getElementById("editPassword");

  if (editUserId) editUserId.value = userId;
  if (editFirstName) editFirstName.value = user.firstName;
  if (editSecondName) editSecondName.value = user.secondName;
  if (editEmail) editEmail.value = user.email;
  if (editPhone) editPhone.value = user.phone;
  if (editGrade) editGrade.value = user.grade;
  if (editPassword) editPassword.value = "";

  if (editUserModal) editUserModal.classList.add("active");
}

function closeEditUserModal() {
  editUserModal.classList.remove("active");
}

if (editUserForm)
  editUserForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const userId = document.getElementById("editUserId")?.value;
    const firstName = document.getElementById("editFirstName")?.value;
    const secondName = document.getElementById("editSecondName")?.value;
    const email = document.getElementById("editEmail")?.value;
    const phone = document.getElementById("editPhone")?.value;
    const grade = document.getElementById("editGrade")?.value;
    const password = document.getElementById("editPassword")?.value;
    const editSubmitBtn = document.getElementById("editSubmitBtn");
    const editBtnText = document.getElementById("editBtnText");
    const editBtnLoading = document.getElementById("editBtnLoading");

    if (editSubmitBtn) editSubmitBtn.disabled = true;
    if (editBtnText) editBtnText.style.display = "none";
    if (editBtnLoading) editBtnLoading.style.display = "inline";

    try {
      const updateData = {
        firstName,
        secondName,
        email,
        phone,
        grade,
      };
      if (password) {
        if (password.length < 8) {
          throw new Error("كلمة المرور يجب أن تكون 8 أحرف على الأقل");
        }
        if (!/[A-Z]/.test(password)) {
          throw new Error("كلمة المرور يجب أن تحتوي على حرف كبير واحد");
        }
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
          throw new Error("كلمة المرور يجب أن تحتوي على رمز واحد (!@#$%...)");
        }
        updateData.password = password;
      }

      const response = await fetch(`/api/admin/users/${userId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updateData),
      });

      if (response.ok) {
        closeEditUserModal();
        Swal.fire({
          title: "تم بنجاح!",
          text: "تم تحديث بيانات المستخدم بنجاح",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadUsers();
      } else {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.message || "فشل تحديث بيانات المستخدم";
        if (
          errorMessage.includes("contact carl") ||
          errorMessage.includes("تواصل مع كارل")
        ) {
          Swal.fire({
            title: "غير مسموح!",
            text: "يرجى التواصل مع كارل لتعديل هذا المستخدم",
            icon: "warning",
            confirmButtonText: "حسناً",
            confirmButtonColor: "#ffcc00",
          });
        } else {
          throw new Error(errorMessage);
        }
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر تحديث بيانات المستخدم",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    } finally {
      if (editSubmitBtn) editSubmitBtn.disabled = false;
      if (editBtnText) editBtnText.style.display = "inline";
      if (editBtnLoading) editBtnLoading.style.display = "none";
    }
  });

if (closeEditModal)
  closeEditModal.addEventListener("click", closeEditUserModal);
if (cancelEditModal)
  cancelEditModal.addEventListener("click", closeEditUserModal);

function closeTakePointsModal() {
  if (takePointsModal && takePointsModal.classList.contains("active")) {
    takePointsModal.classList.remove("active");
  }
}

async function openTakePointsModal(userId, username) {
  const { value: formValues } = await Swal.fire({
    title: "خصم نقاط",
    html: `
          <input id="swal-remove-amount" class="swal2-input" placeholder="عدد النقاط" type="number" min="1" required>
          <input id="swal-remove-reason" class="swal2-input" placeholder="السبب (اختياري)">
      `,
    focusConfirm: false,
    showCancelButton: true,
    confirmButtonText: "خصم",
    cancelButtonText: "إلغاء",
    confirmButtonColor: "#e74c3c",
    cancelButtonColor: "#666",
    preConfirm: () => {
      return {
        amount: document.getElementById("swal-remove-amount").value,
        reason: document.getElementById("swal-remove-reason").value,
      };
    },
  });

  if (formValues && formValues.amount) {
    try {
      const response = await fetch(`/api/admin/users/${userId}/remove-points`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formValues),
      });
      if (response.ok) {
        Swal.fire({
          title: "تم بنجاح!",
          text: `تم خصم ${formValues.amount} نقطة من المستخدم @${username}`,
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadUsers(true);
      } else {
        throw new Error("فشل خصم النقاط");
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر خصم النقاط",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    }
  }
}

function openBanModal(userId, username) {
  const banUserId = document.getElementById("banUserId");
  const banType = document.getElementById("banType");
  const banReason = document.getElementById("banReason");
  const banDurationPermanent = document.getElementById("banDurationPermanent");
  const banDurationTemporary = document.getElementById("banDurationTemporary");
  const banDays = document.getElementById("banDays");
  const banDaysWrap = document.getElementById("banDaysWrap");

  if (banUserId) banUserId.value = userId;
  if (banType) banType.value = "all";
  if (banReason) banReason.value = "";
  if (banDurationPermanent) banDurationPermanent.checked = true;
  if (banDurationTemporary) banDurationTemporary.checked = false;
  if (banDays) banDays.value = "";
  if (banDaysWrap) banDaysWrap.style.display = "none";

  if (banModal) banModal.classList.add("active");
}
const banDurationTemporary = document.getElementById("banDurationTemporary");
if (banDurationTemporary) {
  banDurationTemporary.addEventListener("change", function () {
    const wrap = document.getElementById("banDaysWrap");
    if (wrap) wrap.style.display = this.checked ? "block" : "none";
  });
}

const banDurationPermanent = document.getElementById("banDurationPermanent");
if (banDurationPermanent) {
  banDurationPermanent.addEventListener("change", function () {
    const wrap = document.getElementById("banDaysWrap");
    if (wrap) wrap.style.display = "none";
  });
}

function closeBanModal() {
  if (banModal && banModal.classList.contains("active")) {
    banModal.classList.remove("active");
  }
}

if (banForm)
  banForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const userId = document.getElementById("banUserId")?.value;
    const banType = document.getElementById("banType")?.value;
    const reason = document.getElementById("banReason")?.value;

    const banSubmitBtn = document.getElementById("banSubmitBtn");
    const banBtnText = document.getElementById("banBtnText");
    const banBtnLoading = document.getElementById("banBtnLoading");

    if (!banType) {
      Swal.fire({
        title: "خطأ!",
        text: "يرجى اختيار نوع الحظر",
        icon: "error",
        confirmButtonText: "حسناً",
      });
      return;
    }
    const duration =
      document.querySelector('input[name="banDuration"]:checked')?.value ||
      "permanent";
    const daysInput = document.getElementById("banDays");
    const days = duration === "temporary" && daysInput ? daysInput.value : null;
    if (duration === "temporary" && (!days || parseInt(days, 10) < 1)) {
      Swal.fire({
        title: "خطأ!",
        text: "يرجى إدخال عدد الأيام (1 أو أكثر)",
        icon: "error",
        confirmButtonText: "حسناً",
      });
      return;
    }

    if (banSubmitBtn) banSubmitBtn.disabled = true;
    if (banBtnText) banBtnText.style.display = "none";
    if (banBtnLoading) banBtnLoading.style.display = "inline";

    try {
      const userResponse = await fetch(`/api/admin/users/${userId}`);

      if (!userResponse.ok) {
        if (userResponse.status === 403) {
          throw new Error("ليس لديك صلاحية للوصول إلى بيانات هذا المستخدم");
        } else if (userResponse.status === 404) {
          throw new Error("المستخدم غير موجود");
        } else {
          throw new Error(`فشل تحميل بيانات المستخدم (${userResponse.status})`);
        }
      }

      const user = await userResponse.json();

      if (!user || !user.username) {
        throw new Error("بيانات المستخدم غير صحيحة");
      }

      const response = await fetch(`/api/banned-users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: user.username,
          banType: banType,
          reason: reason,
          duration: duration,
          days:
            duration === "temporary" && daysInput
              ? parseInt(daysInput.value, 10)
              : null,
        }),
      });

      if (response.ok) {
        closeBanModal();
        Swal.fire({
          title: "تم بنجاح!",
          text: "تم حظر المستخدم بنجاح",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadUsers();
        loadBannedUsers();
      } else {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || "فشل حظر المستخدم");
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر حظر المستخدم",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    } finally {
      if (banSubmitBtn) banSubmitBtn.disabled = false;
      if (banBtnText) banBtnText.style.display = "inline";
      if (banBtnLoading) banBtnLoading.style.display = "none";
    }
  });

if (closeBanModalBtn) closeBanModalBtn.addEventListener("click", closeBanModal);
if (cancelBanModal) cancelBanModal.addEventListener("click", closeBanModal);

async function loadBannedUsers() {
  try {
    const response = await fetch("/api/banned-users");

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const bannedUsers = await response.json();

    if (!Array.isArray(bannedUsers)) {
      console.error("API returned non-array response:", bannedUsers);
      throw new Error("Invalid response format from server");
    }

    allBannedUsers = bannedUsers;

    if (!bannedUsers || bannedUsers.length === 0) {
      if (bannedUsersList) {
        bannedUsersList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-user-check"></i>
                    <h3>لا يوجد مستخدمون محظورون</h3>
                    <p>لا يوجد مستخدمون محظورون حالياً</p>
                </div>
            `;
      }
      return;
    }

    displayBannedUsers(bannedUsers);
  } catch (error) {
    console.error("Error loading banned users:", error);
    if (bannedUsersList) {
      bannedUsersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-circle"></i>
                <h3>حدث خطأ</h3>
                <p>تعذر تحميل بيانات المستخدمين المحظورين. يرجى المحاولة مرة أخرى.</p>
            </div>
        `;
    }
  }
}

function displayBannedUsers(bannedUsers) {
  if (!Array.isArray(bannedUsers)) {
    console.error(
      "displayBannedUsers: bannedUsers is not an array",
      bannedUsers,
    );
    bannedUsersList.innerHTML = `
          <div class="empty-state">
              <i class="fas fa-exclamation-circle"></i>
              <h3>حدث خطأ</h3>
              <p>بيانات غير صحيحة</p>
          </div>
      `;
    return;
  }

  const sorted = [...bannedUsers].sort((a, b) => {
    const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0;
    const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0;
    return bTime - aTime;
  });

  bannedUsersList.innerHTML = sorted
    .map((ban) => {
      const banTypeText =
        {
          login: "حظر تسجيل الدخول",
          forms: "حظر النماذج",
          all: "حظر كامل",
        }[ban.banType] || ban.banType;

      const banTypeBadge =
        {
          login:
            '<span class="status-badge" style="background: #f39c12; color: white;">🔐 حظر تسجيل الدخول</span>',
          forms:
            '<span class="status-badge" style="background: #e67e22; color: white;">📝 حظر النماذج</span>',
          all: '<span class="status-badge" style="background: #e74c3c; color: white;">🚫 حظر كامل</span>',
        }[ban.banType] ||
        '<span class="status-badge banned-badge">🔴 محظور</span>';

      const banDate = ban.createdAt
        ? new Date(ban.createdAt).toLocaleString("ar-EG")
        : "غير محدد";

      const banDateAgo = ban.createdAt
        ? formatTimeAgo(new Date(ban.createdAt))
        : "";

      return `
                <div class="user-card">
                    <div class="user-card-header">
                        <div class="user-avatar-large banned-avatar">
                            <i class="fas fa-user-slash"></i>
                        </div>
                        <div class="user-main-info">
                            <h3>@${ban.username}</h3>
                            <div class="user-badges">
                                ${banTypeBadge}
                            </div>
                            <div class="user-status-info">
                                <small class="last-login-text">تاريخ الحظر: ${banDateAgo ? banDateAgo : banDate}</small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="user-card-details">
                        <div class="detail-row">
                            <span class="detail-label">اسم المستخدم:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">@${ban.username}</span>
                              <button class="copy-btn" type="button" title="نسخ اسم المستخدم" onclick="copyText('${(
                                ban.username || ""
                              ).replace(/'/g, "\\'")}')">
                                <i class="fas fa-copy"></i>
                              </button>
                            </span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">نوع الحظر:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${banTypeText}</span>
                            </span>
                        </div>
                        ${
                          ban.reason
                            ? `
                        <div class="detail-row">
                            <span class="detail-label">السبب:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${ban.reason}</span>
                            </span>
                        </div>
                        `
                            : ""
                        }
                        <div class="detail-row">
                            <span class="detail-label">تاريخ الحظر:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${banDate}</span>
                            </span>
                        </div>
                        ${
                          ban.expiresAt
                            ? `
                        <div class="detail-row">
                            <span class="detail-label">ينتهي في:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">${new Date(ban.expiresAt).toLocaleString("ar-EG")}</span>
                            </span>
                        </div>
                        `
                            : `
                        <div class="detail-row">
                            <span class="detail-label">المدة:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">دائم</span>
                            </span>
                        </div>
                        `
                        }
                        ${
                          ban.createdBy
                            ? `
                        <div class="detail-row">
                            <span class="detail-label">حظر بواسطة:</span>
                            <span class="detail-value-wrap">
                              <span class="detail-value">@${ban.createdBy}</span>
                            </span>
                        </div>
                        `
                            : ""
                        }
                    </div>
                    
                    <div class="user-card-actions">
                        <button class="action-btn unban-btn" onclick="unbanUser('${ban.username.replace(
                          /'/g,
                          "\\'",
                        )}')" style="background: #27ae60; color: white;">
                            <i class="fas fa-unlock"></i>
                            إلغاء الحظر
                        </button>
                    </div>
                </div>
            `;
    })
    .join("");
}

function searchUsers() {
  const raw = (searchInput?.value || "").toString();
  const next = raw.trim();
  currentSearch = next;
  if (currentSearch) {
    if (clearSearch) clearSearch.style.display = "flex";
  } else {
    if (clearSearch) clearSearch.style.display = "none";
  }

  loadUsers(true);
}

async function givePoints(userId, username) {
  const { value: formValues } = await Swal.fire({
    title: "إعطاء نقاط",
    html: `
          <input id="swal-amount" class="swal2-input" placeholder="عدد النقاط" type="number" min="1" required>
          <input id="swal-reason" class="swal2-input" placeholder="السبب (اختياري)">
      `,
    focusConfirm: false,
    showCancelButton: true,
    confirmButtonText: "إعطاء",
    cancelButtonText: "إلغاء",
    confirmButtonColor: "#27ae60",
    cancelButtonColor: "#666",
    preConfirm: () => {
      return {
        amount: document.getElementById("swal-amount").value,
        reason: document.getElementById("swal-reason").value,
      };
    },
  });

  if (formValues && formValues.amount) {
    try {
      const response = await fetch(`/api/admin/users/${userId}/give-points`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formValues),
      });

      if (response.ok) {
        Swal.fire({
          title: "تم بنجاح!",
          text: `تم إعطاء ${formValues.amount} نقطة للمستخدم @${username}`,
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadUsers(true);
      } else {
        throw new Error("فشل إعطاء النقاط");
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر إعطاء النقاط",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    }
  }
}

async function deleteUser(userId, username) {
  const user = allUsers.find((u) => u._id === userId);
  if (user) {
    if (
      currentAdminUsername &&
      user.username.toLowerCase() === currentAdminUsername.toLowerCase()
    ) {
      Swal.fire({
        title: "غير مسموح!",
        text: "لا يمكنك حذف حسابك الخاص",
        icon: "warning",
        confirmButtonText: "حسناً",
        confirmButtonColor: "#ffcc00",
      });
      return;
    }

    if (user.role === "admin" || user.role === "leadadmin") {
      Swal.fire({
        title: "غير مسموح!",
        text: "يرجى التواصل مع كارل لحذف هذا المستخدم",
        icon: "warning",
        confirmButtonText: "حسناً",
        confirmButtonColor: "#ffcc00",
      });
      return;
    }

    if (user._isLocal === true) {
      Swal.fire({
        title: "غير مسموح!",
        text: "يرجى التواصل مع كارل لحذف هذا المستخدم",
        icon: "warning",
        confirmButtonText: "حسناً",
        confirmButtonColor: "#ffcc00",
      });
      return;
    }
  }

  const result = await Swal.fire({
    title: "هل أنت متأكد؟",
    text: `هل أنت متأكد أنك تريد حذف المستخدم "${username}"؟ هذا الإجراء لا يمكن التراجع عنه!`,
    icon: "warning",
    showCancelButton: true,
    confirmButtonText: "نعم، احذف",
    cancelButtonText: "إلغاء",
    confirmButtonColor: "#e74c3c",
    cancelButtonColor: "#666",
  });

  if (result.isConfirmed) {
    Swal.fire({
      title: "جاري الحذف...",
      text: "يرجى الانتظار جاري حذف المستخدم",
      icon: "info",
      showConfirmButton: false,
      allowOutsideClick: false,
      didOpen: () => {
        Swal.showLoading();
      },
    });

    try {
      const response = await fetch(`/api/admin/users/${userId}`, {
        method: "DELETE",
      });

      Swal.close();

      if (response.ok) {
        Swal.fire({
          title: "تم بنجاح!",
          text: "تم حذف المستخدم بنجاح",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadUsers();
      } else {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.message || "فشل حذف المستخدم";

        if (
          errorMessage.includes("contact carl") ||
          errorMessage.includes("تواصل مع كارل") ||
          errorMessage.includes("حسابك الخاص")
        ) {
          Swal.fire({
            title: "غير مسموح!",
            text: errorMessage.includes("حسابك الخاص")
              ? "لا يمكنك حذف حسابك الخاص"
              : "يرجى التواصل مع كارل لحذف هذا المستخدم",
            icon: "warning",
            confirmButtonText: "حسناً",
            confirmButtonColor: "#ffcc00",
          });
        } else {
          throw new Error(errorMessage);
        }
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر حذف المستخدم",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    }
  }
}

async function unbanUser(username) {
  const result = await Swal.fire({
    title: "هل أنت متأكد؟",
    text: `هل أنت متأكد أنك تريد إلغاء حظر المستخدم "${username}"؟`,
    icon: "question",
    showCancelButton: true,
    confirmButtonText: "نعم، إلغاء الحظر",
    cancelButtonText: "إلغاء",
    confirmButtonColor: "#27ae60",
    cancelButtonColor: "#666",
  });

  if (result.isConfirmed) {
    Swal.fire({
      title: "جاري إلغاء الحظر...",
      text: "يرجى الانتظار جاري إلغاء حظر المستخدم",
      icon: "info",
      showConfirmButton: false,
      allowOutsideClick: false,
      didOpen: () => {
        Swal.showLoading();
      },
    });

    try {
      const response = await fetch(
        `/api/banned-users/${encodeURIComponent(username)}`,
        { method: "DELETE" },
      );

      Swal.close();

      if (response.ok) {
        Swal.fire({
          title: "تم بنجاح!",
          text: "تم إلغاء حظر المستخدم بنجاح",
          icon: "success",
          confirmButtonText: "حسناً",
          confirmButtonColor: "#ffcc00",
        });
        loadUsers();
        loadBannedUsers();
      } else {
        throw new Error("فشل إلغاء حظر المستخدم");
      }
    } catch (error) {
      Swal.fire({
        title: "خطأ!",
        text: error.message || "تعذر إلغاء حظر المستخدم",
        icon: "error",
        confirmButtonText: "حسناً",
      });
    }
  }
}

function toggleView() {
  if (bannedSection && bannedSection.style.display === "none") {
    if (usersSection) usersSection.style.display = "none";
    bannedSection.style.display = "block";
    if (toggleViewBtn)
      toggleViewBtn.innerHTML = '<i class="fas fa-users"></i> عرض النشطين';

    loadBannedUsers();
  } else {
    if (usersSection) usersSection.style.display = "block";
    if (bannedSection) bannedSection.style.display = "none";
    if (toggleViewBtn)
      toggleViewBtn.innerHTML = '<i class="fas fa-ban"></i> عرض المحظورين';

    displayUsersByCategory(currentCategory);
  }
}
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

if (logoutBtn) logoutBtn.addEventListener("click", performLogout);
if (logoutBtnMobile) logoutBtnMobile.addEventListener("click", performLogout);
if (toggleViewBtn) toggleViewBtn.addEventListener("click", toggleView);
if (refreshUsersBtn) {
  refreshUsersBtn.addEventListener("click", () => {
    loadUsers();
    if (bannedSection && bannedSection.style.display !== "none") {
      loadBannedUsers();
    }
  });
}
if (searchInput) searchInput.addEventListener("input", searchUsers);
if (clearSearch) {
  clearSearch.addEventListener("click", () => {
    if (searchInput) searchInput.value = "";
    clearSearch.style.display = "none";
    currentSearch = "";
    loadUsers(true);
  });
}

categoryTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    categoryTabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    currentCategory = tab.dataset.category;
    loadUsers(true);
  });
});

document.addEventListener("click", function (event) {
  if (window.innerWidth <= 992 && sidebar && mobileToggle) {
    if (
      !sidebar.contains(event.target) &&
      !mobileToggle.contains(event.target)
    ) {
      sidebar.classList.remove("active");
      const spans = mobileToggle.querySelectorAll("span");
      spans[0].style.transform = "none";
      spans[1].style.opacity = "1";
      spans[2].style.transform = "none";
    }
  }
});

document.addEventListener("DOMContentLoaded", function () {
  loadUserInfo();
  loadUsers();
});

document.addEventListener("keydown", function (event) {
  if (event.key === "Escape") {
    closeEditUserModal();
    closeTakePointsModal();
    closeBanModal();
  }
});

window.addEventListener("click", function (event) {
  if (event.target === editUserModal) closeEditUserModal();
  if (event.target === takePointsModal) closeTakePointsModal();
  if (event.target === banModal) closeBanModal();
});

if (categoryToggle) {
  categoryToggle.addEventListener("click", function (e) {
    e.stopPropagation();
    e.preventDefault();
    categoryDropdown.classList.toggle("active");

    if (categoryDropdown.classList.contains("active")) {
      dropdownMenu.style.animation = "fadeInUp 0.3s ease";
    }
  });
}

categoryOptions.forEach((option) => {
  option.addEventListener("click", function () {
    const category = this.dataset.category;

    categoryOptions.forEach((opt) => opt.classList.remove("active"));

    this.classList.add("active");

    currentCategory = category;
    loadUsers(true);

    const optionText = this.textContent
      .replace(this.querySelector(".category-count").textContent, "")
      .trim();
    categoryToggle.innerHTML = `
      <i class="fas fa-filter"></i>
      ${optionText}
      <i class="fas fa-chevron-down"></i>
  `;

    categoryDropdown.classList.remove("active");
  });
});

document.addEventListener("click", function (e) {
  if (categoryDropdown && !categoryDropdown.contains(e.target)) {
    categoryDropdown.classList.remove("active");
  }
});

document.addEventListener("keydown", function (e) {
  if (e.key === "Escape" && categoryDropdown) {
    categoryDropdown.classList.remove("active");
  }
});

async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const temp = document.createElement("textarea");
      temp.value = text;
      document.body.appendChild(temp);
      temp.select();
      document.execCommand("copy");
      document.body.removeChild(temp);
    }

    await Swal.fire({
      title: "تم النسخ",
      text: "تم نسخ البيانات إلى الحافظة بنجاح",
      icon: "success",
      confirmButtonText: "حسناً",
      confirmButtonColor: "#ffcc00",
      timer: 1600,
      timerProgressBar: true,
    });
  } catch (e) {
    await Swal.fire({
      title: "فشل النسخ",
      text: "تعذر نسخ البيانات. حاول مرة أخرى.",
      icon: "error",
      confirmButtonText: "حسناً",
      confirmButtonColor: "#e74c3c",
    });
  }
}

function getUserStatus(user) {
  if (isUserBanned(user)) return "banned";

  const lastActivity = user?.lastActivity ? new Date(user.lastActivity) : null;
  if (!lastActivity || Number.isNaN(lastActivity.getTime())) return "offline";

  const now = Date.now();
  const diffMs = now - lastActivity.getTime();
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffDays = diffMs / (24 * 60 * 60 * 1000);

  const OFFLINE_THRESHOLD_DAYS = 7;
  if (diffDays > OFFLINE_THRESHOLD_DAYS) return "offline";

  const ONLINE_THRESHOLD_MINUTES = 2;
  const IDLE_THRESHOLD_MINUTES = 30;

  if (diffMinutes <= ONLINE_THRESHOLD_MINUTES) return "online";
  if (diffMinutes <= IDLE_THRESHOLD_MINUTES) return "idle";

  return "signed-in";
}

function isUserBanned(user) {
  return allBannedUsers.some((banned) => banned.username === user.username);
}

function getStatusBadge(status) {
  const badges = {
    online: '<span class="status-badge online-badge">🟢 متصل</span>',
    idle: '<span class="status-badge idle-badge">🟠 غير نشط</span>',
    "signed-in":
      '<span class="status-badge signed-in-badge">🔵 مسجل دخول</span>',
    "signed-out":
      '<span class="status-badge signed-out-badge">⚫ غير متصل</span>',
    offline:
      '<span class="status-badge offline-badge">⚫ غير متصل منذ فترة</span>',
    banned: '<span class="status-badge banned-badge">🔴 محظور</span>',
  };

  return badges[status] || badges["offline"];
}

function getStatusDescription(status) {
  const descriptions = {
    online: "متصل",
    idle: "غير نشط",
    "signed-in": "مسجل دخول",
    "signed-out": "غير متصل",
    offline: "غير متصل منذ فترة",
    banned: "المستخدم محظور",
  };

  return descriptions[status] || "غير متصل";
}

function formatTimeAgo(date) {
  const now = new Date();
  const diffMs = now - date;
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMinutes < 1) {
    return "الآن";
  } else if (diffMinutes < 60) {
    return `منذ ${diffMinutes} دقيقة`;
  } else if (diffHours < 24) {
    return `منذ ${diffHours} ساعة`;
  } else if (diffDays < 7) {
    return `منذ ${diffDays} يوم`;
  } else {
    return date.toLocaleDateString("ar-EG");
  }
}
window.openEditUserModal = openEditUserModal;
window.closeEditUserModal = closeEditUserModal;
window.generatePasswordResetLink = generatePasswordResetLink;
window.showPasswordResetLinks = showPasswordResetLinks;
window.logoutAllDevices = logoutAllDevices;
window.givePoints = givePoints;
window.openTakePointsModal = openTakePointsModal;
window.deleteUser = deleteUser;
window.copyText = copyText;
window.openBanModal = openBanModal;
window.unbanUser = unbanUser;
window.loadUsers = loadUsers;
