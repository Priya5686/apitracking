async function getCSRFToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (!metaTag) {
        alert("CSRF token is missing or invalid. Please refresh the page.");
        return "";
    }
    return metaTag.content;
}
window.onload = () => {
    const loginForm = document.querySelector("form");
    loginForm.addEventListener("submit", (event) => {
        event.preventDefault();

        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        if (!email || !password) {
            alert("Please enter both email and password.");
            return;
        }
        loginForm.submit();
    });
};
