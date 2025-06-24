document.addEventListener('DOMContentLoaded', function() {
    // Handle dropdown menu
    const profileDropdown = document.querySelector('.profile-dropdown');
    const dropdownContent = document.querySelector('.dropdown-content');

    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
        if (!profileDropdown.contains(event.target)) {
            dropdownContent.style.opacity = '0';
            dropdownContent.style.visibility = 'hidden';
            dropdownContent.style.transform = 'translateY(10px)';
        }
    });

    // Handle search functionality
    const searchInput = document.querySelector('.search-bar input');
    const searchButton = document.querySelector('.search-bar button');

    if (searchInput && searchButton) {
        searchButton.addEventListener('click', function() {
            handleSearch(searchInput.value);
        });

        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                handleSearch(searchInput.value);
            }
        });
    }
});

function handleSearch(query) {
    // Implement search functionality here
    console.log('Searching for:', query);
    // You can add your search implementation here
} 