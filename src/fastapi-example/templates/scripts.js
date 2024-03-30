// Generate HTML for a post
function generatePostHTML(post) {
    return `<div class="post" data-post-id="${post.id}">
                <h3><a href="{{encrypt_value('/posts/', request)}}${post.id}" class="post-title">${post.title}</a></h3>
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
    fetch('{{encrypt_value("/posts/", request)}}')
        .then(response => response.json())
        .then(data => {
            const postsContainer = document.querySelector('.posts-section');
            data.posts.forEach(post => {
                postsContainer.insertAdjacentHTML('afterbegin', generatePostHTML(post));

                const newPostElement = postsContainer.firstChild;
                newPostElement.addEventListener('click', () => {
                    window.location.href = `/posts/${post.id}`;
                });
            });
        })
        .catch(error => console.error('Error loading posts:', error));
}

function submitVote(postId, voteValue) {
    const payload = {
        post_id: postId,
        user_vote: voteValue
    };

    fetch('{{encrypt_value("/vote/", request)}}', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                return response.text().then(errorMessage => {
                    throw new Error('Response was not ok. ' + errorMessage);
                });
            }
        })
        .then(newScore => {
            const postElement = document.querySelector(`.post[data-post-id="${postId}"] .vote-count`);
            if (postElement) {
                postElement.textContent = newScore;
            } else {
                console.error('Post element not found.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert(error);
        });
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
            fetch('{{encrypt_value("/posts/", request)}}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ title, content, votes: 0 }),
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
            submitVote(postId, parseInt(voteValue));
        }
    });
});