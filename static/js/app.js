// Timer functionality
function startTimer(linkType, minutes) {
    const endTime = new Date().getTime() + (minutes * 60 * 1000);
    const timerId = `timer-${linkType}`;
    const buttonId = `btn-${linkType}`;

    const timer = setInterval(function() {
        const now = new Date().getTime();
        const distance = endTime - now;

        if (distance < 0) {
            clearInterval(timer);
            document.getElementById(timerId).innerHTML = "Ready!";
            document.getElementById(buttonId).classList.remove('disabled');
            document.getElementById(buttonId).disabled = false;
            return;
        }

        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

        document.getElementById(timerId).innerHTML = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    }, 1000);
}

// Purchase confirmation
function confirmPurchase(itemName, coins) {
    return confirm(`Are you sure you want to purchase ${itemName} for ${coins} coins?`);
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        alert('Copied to clipboard!');
    });
}

// Auto refresh purchase history
function refreshPurchaseHistory() {
    fetch('/purchase_history_data')
        .then(response => response.json())
        .then(data => {
            // Update purchase history table
            updatePurchaseTable(data);
        })
        .catch(error => console.error('Error:', error));
}

function updatePurchaseTable(purchases) {
    const tbody = document.getElementById('purchase-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    purchases.forEach(purchase => {
        const row = `
            <tr>
                <td>${purchase.item_name}</td>
                <td>${purchase.coins_spent}</td>
                <td><span class="status-${purchase.status}">${purchase.status}</span></td>
                <td>${purchase.created_at}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// Helper function for notifications (add this if not already present)
function showNotification(message, type) {
    // This is a placeholder. In a real app, you'd use a notification library
    // or create DOM elements for notifications.
    console.log(`[${type.toUpperCase()}] ${message}`);
    alert(`${type.toUpperCase()}: ${message}`);
}

function generateLink(linkType) {
    const button = document.getElementById(`btn-${linkType}`);
    const originalText = button.innerHTML;

    // Show loading state
    button.innerHTML = '<span class="loading"></span> Generating...';
    button.disabled = true;

    fetch(`/generate_link/${linkType}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                button.innerHTML = '✅ Link Generated!';

                // Open link after short delay
                setTimeout(() => {
                    window.open(data.shortened_url, '_blank');
                    button.classList.add('disabled');
                    button.innerHTML = '<i class="fas fa-clock"></i> Please Wait...';
                }, 1000);
            } else {
                button.innerHTML = originalText;
                button.disabled = false;
                showNotification('Error: ' + data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            button.innerHTML = originalText;
            button.disabled = false;
            showNotification('An error occurred', 'error');
        });
}

// Initialize timers on page load
document.addEventListener('DOMContentLoaded', function() {
    // Refresh purchase history every 30 seconds
    if (document.getElementById('purchase-tbody')) {
        setInterval(refreshPurchaseHistory, 30000);
    }

    // Initialize any existing timers
    const timerElements = document.querySelectorAll('[data-timer]');
    timerElements.forEach(element => {
        const linkType = element.dataset.linkType;
        const minutes = parseInt(element.dataset.timer);
        if (minutes > 0) {
            startTimer(linkType, minutes);
        }
    });
});