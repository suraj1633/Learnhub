// Course content management
document.addEventListener('DOMContentLoaded', function() {
    // Add content section
    const addContentBtn = document.getElementById('add-content-btn');
    const contentTemplate = document.getElementById('content-template');
    const contentsContainer = document.getElementById('contents-container');
    
    if (addContentBtn && contentTemplate && contentsContainer) {
        let contentCount = contentsContainer.children.length;
        
        addContentBtn.addEventListener('click', function() {
            const newContent = contentTemplate.content.cloneNode(true);
            const newElements = newContent.querySelectorAll('[id]');
            
            // Update IDs to be unique
            newElements.forEach(el => {
                el.id = `${el.id}-${contentCount}`;
                if (el.tagName === 'LABEL' && el.htmlFor) {
                    el.htmlFor = `${el.htmlFor}-${contentCount}`;
                }
            });
            
            contentsContainer.appendChild(newContent);
            contentCount++;
        });
    }

    // Handle content deletion
    contentsContainer?.addEventListener('click', function(e) {
        if (e.target.classList.contains('remove-content')) {
            e.target.closest('.content-item').remove();
        }
    });
});