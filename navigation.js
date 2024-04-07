window.onpopstate = function(event) {
    // Redirect to the main dashboard if not already there
    if (location.pathname !== '/index.html') {
        history.pushState(null, null, '/index.html');
        redirectToMainDashboard();
    }
};

// Function to redirect to the main dashboard
function redirectToMainDashboard() {
    window.location.href = '/';
}