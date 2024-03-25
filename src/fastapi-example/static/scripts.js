// Generate HTML for a post
function generatePostHTML(post) {
    return `<div class="post" data-post-id="${post.id}">
                <h3>${post.title}</h3>
                <p>${post.content}</p>
                <p>Author: ${post.author}</p>
                <div class="vote-buttons">
                    <button class="vote-button upvote" data-vote="1"><i class="fas fa-thumbs-up"></i></button>
                    <span class="vote-count">${post.votes}</span>
                    <button class="vote-button downvote" data-vote="-1"><i class="fas fa-thumbs-down"></i></button>
                </div>
            </div>`;
}


// Load and display posts on page load
function loadAndDisplayPosts() {
    fetch('/posts/')
        .then(response => response.json())
        .then(data => {
            const postsContainer = document.querySelector('.posts-section');
            data.posts.forEach(post => {
                postsContainer.insertAdjacentHTML('afterbegin', generatePostHTML(post));
            });
        })
        .catch(error => console.error('Error loading posts:', error));
}

function submitVote(postId, voteValue) {
    const payload = {
        postId: postId,
        vote: voteValue
    };

    fetch('/vote', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const postElement = document.querySelector(`.post[data-post-id="${postId}"] .vote-count`);
                postElement.textContent = data.newVoteTotal;
            } else {
                alert(data.message);
            }
        })
        .catch(error => console.error('Error:', error));
}


document.addEventListener('DOMContentLoaded', function () {
    const createPostButton = document.getElementById('createPostButton');
    const createPostForm = document.getElementById('createPostForm');
    const submitPostButton = document.getElementById('submitPost');
    const cancelPostButton = document.getElementById('cancelPost');

    // Function to toggle the visibility of the post creation form
    function togglePostFormDisplay(display = 'none') {
        createPostForm.style.display = display;
        createPostButton.style.display = display === 'none' ? 'block' : 'none';
    }

    // Show the form to create a post when the button is clicked
    if (createPostButton) {
        createPostButton.addEventListener('click', function () {
            togglePostFormDisplay('block');
        });
    }

    // Hide the form when the cancel button is clicked
    if (cancelPostButton) {
        cancelPostButton.addEventListener('click', function () {
            togglePostFormDisplay('none');
        });
    }

    // Handling the submission of a new post
    submitPostButton.addEventListener('click', function (e) {
        e.preventDefault();

        const title = document.getElementById('postTitle').value.trim();
        const content = document.getElementById('postContent').value.trim();

        if (title && content) {
            fetch('/posts/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ title, content, author: 'AuthorName', votes: 0 }),
            })
                .then(response => response.json())
                .then(post => {
                    const postsContainer = document.querySelector('.posts-section');
                    postsContainer.insertAdjacentHTML('afterbegin', generatePostHTML(post));
                    document.getElementById('postTitle').value = '';
                    document.getElementById('postContent').value = '';
                    togglePostFormDisplay('none');
                })
                .catch(error => console.error('Error:', error));
        }
    });



    loadAndDisplayPosts();

    document.querySelector('.posts-section').addEventListener('click', function (e) {
        if (e.target.classList.contains('vote-button')) {
            const postId = e.target.closest('.post').dataset.postId;
            const voteValue = e.target.dataset.vote;
            submitVote(postId, voteValue);
        }
    });
});