// Course filtering and search
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('course-search');
    const categoryFilter = document.getElementById('category-filter');
    const courseCards = document.querySelectorAll('.course-card');
    
    function filterCourses() {
        const searchTerm = searchInput.value.toLowerCase();
        const category = categoryFilter.value;
        
        courseCards.forEach(card => {
            const title = card.dataset.title.toLowerCase();
            const desc = card.dataset.description.toLowerCase();
            const cardCategory = card.dataset.category;
            
            const matchesSearch = title.includes(searchTerm) || desc.includes(searchTerm);
            const matchesCategory = category === 'all' || cardCategory === category;
            
            if (matchesSearch && matchesCategory) {
                card.classList.remove('hidden');
            } else {
                card.classList.add('hidden');
            }
        });
    }
    
    searchInput?.addEventListener('input', filterCourses);
    categoryFilter?.addEventListener('change', filterCourses);

    // Course enrollment
    const enrollButtons = document.querySelectorAll('.enroll-btn');
    enrollButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const courseId = this.dataset.courseId;
            
            try {
                const response = await fetch('/api/enroll', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ course_id: courseId })
                });
                
                const result = await response.json();
                if (result.success) {
                    window.location.href = `/student/courses`;
                } else {
                    alert(result.message || 'Enrollment failed');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred during enrollment');
            }
        });
    });
});