// Smooth scroll behavior
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scrolling to all links
    const links = document.querySelectorAll('a[href^="#"]');
    links.forEach(link => {
        link.addEventListener('click', function(e) {
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

    // Add animation on scroll for practical cards
    const cards = document.querySelectorAll('.practical-card');
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '0';
                entry.target.style.transform = 'translateY(20px)';
                
                setTimeout(() => {
                    entry.target.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, 100);
                
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    cards.forEach(card => {
        observer.observe(card);
    });

    // Category filtering (optional enhancement)
    const legendItems = document.querySelectorAll('.legend-item');
    legendItems.forEach(item => {
        item.addEventListener('click', function() {
            const category = this.getAttribute('data-cat');
            filterByCategory(category);
        });
    });
});

function filterByCategory(category) {
    const cards = document.querySelectorAll('.practical-card');
    cards.forEach(card => {
        if (card.getAttribute('data-category') === category) {
            card.style.display = 'block';
            card.style.animation = 'fadeIn 0.5s ease';
        } else {
            card.style.opacity = '0.3';
        }
    });

    // Reset after 3 seconds
    setTimeout(() => {
        cards.forEach(card => {
            card.style.display = 'block';
            card.style.opacity = '1';
        });
    }, 3000);
}

// Add fade-in animation
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// Add keyboard shortcuts for navigation
document.addEventListener('keydown', function(e) {
    // Left arrow - previous
    if (e.key === 'ArrowLeft') {
        const prevBtn = document.querySelector('.nav-prev');
        if (prevBtn) {
            window.location.href = prevBtn.getAttribute('href');
        }
    }
    
    // Right arrow - next
    if (e.key === 'ArrowRight') {
        const nextBtn = document.querySelector('.nav-next');
        if (nextBtn) {
            window.location.href = nextBtn.getAttribute('href');
        }
    }
    
    // Escape - home
    if (e.key === 'Escape') {
        const homeBtn = document.querySelector('.nav-home');
        if (homeBtn) {
            window.location.href = homeBtn.getAttribute('href');
        }
    }
});

// Add copy functionality for code blocks
document.addEventListener('DOMContentLoaded', function() {
    const codeBlocks = document.querySelectorAll('pre');
    codeBlocks.forEach(block => {
        block.addEventListener('dblclick', function() {
            const text = this.textContent;
            copyToClipboard(text);
            showNotification('Code copied!');
        });
    });
});

function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
}

function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'copy-notification show';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 2000);
}
