// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize course slider functionality
    initializeCourseSlider();
    
    // Initialize testimonial slider
    initializeTestimonialSlider();
});

// Function to initialize course slider
function initializeCourseSlider() {
    const courseSlider = document.querySelector('.course-slider');
    if (!courseSlider) return;

    let isDown = false;
    let startX;
    let scrollLeft;

    courseSlider.addEventListener('mousedown', (e) => {
        isDown = true;
        courseSlider.style.cursor = 'grabbing';
        startX = e.pageX - courseSlider.offsetLeft;
        scrollLeft = courseSlider.scrollLeft;
    });

    courseSlider.addEventListener('mouseleave', () => {
        isDown = false;
        courseSlider.style.cursor = 'grab';
    });

    courseSlider.addEventListener('mouseup', () => {
        isDown = false;
        courseSlider.style.cursor = 'grab';
    });

    courseSlider.addEventListener('mousemove', (e) => {
        if (!isDown) return;
        e.preventDefault();
        const x = e.pageX - courseSlider.offsetLeft;
        const walk = (x - startX) * 2;
        courseSlider.scrollLeft = scrollLeft - walk;
    });
}

// Function to initialize testimonial slider
function initializeTestimonialSlider() {
    const testimonialSlider = document.querySelector('.testimonial-slider');
    if (!testimonialSlider) return;

    let currentSlide = 0;
    const testimonials = testimonialSlider.querySelectorAll('.testimonial');
    if (testimonials.length <= 1) return;

    // Create navigation dots
    const dotsContainer = document.createElement('div');
    dotsContainer.className = 'testimonial-dots';
    testimonials.forEach((_, index) => {
        const dot = document.createElement('button');
        dot.className = 'testimonial-dot';
        dot.addEventListener('click', () => goToSlide(index));
        dotsContainer.appendChild(dot);
    });
    testimonialSlider.appendChild(dotsContainer);

    // Create next/prev buttons
    const createNavButton = (text, className, onClick) => {
        const button = document.createElement('button');
        button.textContent = text;
        button.className = `testimonial-nav ${className}`;
        button.addEventListener('click', onClick);
        return button;
    };

    const prevButton = createNavButton('←', 'prev', () => {
        currentSlide = (currentSlide - 1 + testimonials.length) % testimonials.length;
        updateSlider();
    });

    const nextButton = createNavButton('→', 'next', () => {
        currentSlide = (currentSlide + 1) % testimonials.length;
        updateSlider();
    });

    testimonialSlider.appendChild(prevButton);
    testimonialSlider.appendChild(nextButton);

    // Function to update slider state
    function updateSlider() {
        testimonials.forEach((testimonial, index) => {
            testimonial.style.transform = `translateX(${100 * (index - currentSlide)}%)`;
            testimonial.style.opacity = index === currentSlide ? '1' : '0';
        });

        // Update dots
        dotsContainer.querySelectorAll('.testimonial-dot').forEach((dot, index) => {
            dot.classList.toggle('active', index === currentSlide);
        });
    }

    // Function to go to a specific slide
    function goToSlide(index) {
        currentSlide = index;
        updateSlider();
    }

    // Initialize slider state
    testimonials.forEach((testimonial, index) => {
        testimonial.style.position = 'absolute';
        testimonial.style.transition = 'all 0.5s ease';
    });
    updateSlider();

    // Auto-advance slides
    setInterval(() => {
        currentSlide = (currentSlide + 1) % testimonials.length;
        updateSlider();
    }, 5000);
}

// Add smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
}); 