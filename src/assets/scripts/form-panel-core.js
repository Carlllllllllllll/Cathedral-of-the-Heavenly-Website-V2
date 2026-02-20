const mobileToggle = document.getElementById("mobileToggle");
      const sidebar = document.getElementById("sidebar");
      const logoutBtn = document.getElementById("logoutBtn");
      const logoutBtnMobile = document.getElementById("logoutBtnMobile");
      const gradesToggle = document.getElementById("gradesToggle");
      const gradesSubmenu = document.getElementById("gradesSubmenu");
      const sectionToggles = document.querySelectorAll(".section-toggle");

      function toggleSidebar() {
        if (sidebar && mobileToggle) {
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
      }

      if (mobileToggle) {
        mobileToggle.addEventListener("click", toggleSidebar);
      }

      if (gradesToggle) {
        gradesToggle.addEventListener("click", function (e) {
          e.stopPropagation();
          this.classList.toggle("active");
          const icon = this.querySelector(".toggle-icon");
          if (this.classList.contains("active")) {
            icon.classList.remove("fa-chevron-down");
            icon.classList.add("fa-chevron-up");
            gradesSubmenu.style.maxHeight =
              Math.min(gradesSubmenu.scrollHeight, 400) + "px";
          } else {
            icon.classList.remove("fa-chevron-up");
            icon.classList.add("fa-chevron-down");
            gradesSubmenu.style.maxHeight = "0";
            document
              .querySelectorAll(".section-toggle.active")
              .forEach((toggle) => {
                toggle.classList.remove("active");
                const subIcon = toggle.querySelector(".toggle-icon");
                subIcon.classList.remove("fa-chevron-up");
                subIcon.classList.add("fa-chevron-down");
                const sectionSub = document.querySelector(
                  `.section-submenu[data-section="${toggle.dataset.section}"]`
                );
                if (sectionSub) sectionSub.style.maxHeight = "0";
              });
          }
        });
      }

      sectionToggles.forEach((toggle) => {
        toggle.addEventListener("click", function (e) {
          e.stopPropagation();
          this.classList.toggle("active");
          const icon = this.querySelector(".toggle-icon");
          const sectionSub = document.querySelector(
            `.section-submenu[data-section="${this.dataset.section}"]`
          );

          if (this.classList.contains("active")) {
            icon.classList.remove("fa-chevron-down");
            icon.classList.add("fa-chevron-up");
            sectionSub.style.maxHeight = sectionSub.scrollHeight + "px";
          } else {
            icon.classList.remove("fa-chevron-up");
            icon.classList.add("fa-chevron-down");
            sectionSub.style.maxHeight = "0";
          }
        });
      });

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

      if (logoutBtn) {
        logoutBtn.addEventListener("click", performLogout);
      }
      if (logoutBtnMobile) {
        logoutBtnMobile.addEventListener("click", performLogout);
      }

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