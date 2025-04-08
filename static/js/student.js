// Course progress tracking
document.addEventListener('DOMContentLoaded', function() {
    const progressBars = document.querySelectorAll('.progress-bar');
    
    progressBars.forEach(bar => {
        const progress = bar.dataset.progress;
        bar.style.width = `${progress}%`;
        bar.setAttribute('aria-valuenow', progress);
    });

    // Mark as complete buttons
    const completeButtons = document.querySelectorAll('.mark-complete');
    completeButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const contentId = this.dataset.contentId;
            const courseId = this.dataset.courseId;
            
            try {
                const response = await fetch('/api/update_progress', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        course_id: courseId,
                        content_id: contentId,
                        completed: true
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    this.classList.add('bg-green-500');
                    this.textContent = 'Completed';
                    this.disabled = true;
                }
            } catch (error) {
                console.error('Error:', error);
            }
        });
    });
});