document.addEventListener('DOMContentLoaded', () => {
    const menuIcon = document.getElementById('menuIcon');
    if (menuIcon) {
        menuIcon.addEventListener('click', () => {
            const mobileMenu = document.getElementById('mobileMenu');
            if (mobileMenu) {
                mobileMenu.style.display = (mobileMenu.style.display === 'block') ? 'none' : 'block';
            }
        });
    }

    const scrollToTopButton = document.getElementById('scrollToTop');
    if (scrollToTopButton) {
        scrollToTopButton.addEventListener('click', (e) => {
            e.preventDefault();
            window.scrollTo({
                top: 0,
                behavior: 'smooth',
            });
        });
    }

    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('registerEmail').value.trim();
            const username = document.getElementById('registerUsername').value.trim();
            const password = document.getElementById('registerPassword').value.trim();
            const confirmPassword = document.getElementById('confirmPassword').value.trim();

            if (!email || !username || !password || !confirmPassword) {
                alert('Please fill in all fields.');
                return;
            }

            if (password !== confirmPassword) {
                alert('Passwords do not match.');
                return;
            }

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, username, password }),
                });

                const result = await response.json();
                if (response.ok && result.status === 'success') {
                    window.location.href = '/login';
                } else {
                    console.error('Registration failed:', result.message);
                    alert(`Registration failed: ${result.message}`);
                }
            } catch (error) {
                console.error('Error during registration:', error);
                alert('An error occurred during registration. Please try again.');
            }
        });
    }

    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value.trim();

            if (!email || !password) {
                alert('Please fill in all fields.');
                return;
            }

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password }),
                });

                const result = await response.json();
                if (response.ok && result.status === 'success') {
                    window.location.href = '/unlock';
                } else {
                    console.error('Login failed:', result.message);
                    alert(`Login failed: ${result.message}`);
                }
            } catch (error) {
                console.error('Error during login:', error);
                alert('An error occurred during login. Please try again.');
            }
        });
    }
});




document.addEventListener("DOMContentLoaded", function () {
    // 选择所有带有 smooth-scroll 类的链接
    const links = document.querySelectorAll('.smooth-scroll');

    links.forEach(link => {
        link.addEventListener('click', function (event) {
            event.preventDefault(); // 阻止默认锚点跳转行为
            const targetId = this.getAttribute('href').substring(1); // 获取目标ID
            const targetElement = document.getElementById(targetId);

            if (targetElement) {
                targetElement.scrollIntoView({ behavior: 'smooth' }); // 平滑滚动到目标
            }
        });
    });
});



document.addEventListener("DOMContentLoaded", function () {
    // 检测 URL 是否包含 hash
    const hash = window.location.hash;

    if (hash) {
        // 找到对应的目标元素
        const target = document.querySelector(hash);
        if (target) {
            // 执行平滑滚动
            setTimeout(() => {
                target.scrollIntoView({ behavior: 'smooth' });
            }, 100); // 延迟滚动以确保页面完全加载
        }
    }
});



document.getElementById("profileButton").addEventListener("click", () => {
    const profileDetails = document.getElementById("profileDetails");

    // 切换显示或隐藏
    if (profileDetails.classList.contains("hidden")) {
        // 获取用户信息并显示
        fetch('/get_user_profile')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById("userName").textContent = data.user.username;
                    document.getElementById("userEmail").textContent = data.user.email;
                    document.getElementById("userTier").textContent = data.user.item_number;
                    document.getElementById("userAiquota").textContent = 20-(data.user.query_count);
                } else {
                    alert("Failed to load user profile.");
                }
            })
            .catch(err => {
                console.error("Error fetching profile:", err);
                alert("An error occurred while fetching user profile.");
            });

        profileDetails.classList.remove("hidden");
        profileDetails.style.display = "block";
    } else {
        profileDetails.classList.add("hidden");
        profileDetails.style.display = "none";
    }
});


document.addEventListener("click", (event) => {
    const profileMenu = document.getElementById("profileDetails");
    if (!event.target.closest(".profile-menu")) {
        profileMenu.classList.add("hidden");
        profileMenu.style.display = "none";
    }
});

