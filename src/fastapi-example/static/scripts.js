document.addEventListener('DOMContentLoaded', function () {
    const createPostButton = document.getElementById('createPostButton');
    const createPostForm = document.getElementById('createPostForm');
    const submitPostButton = document.getElementById('submitPost');
    const cancelPostButton = document.getElementById('cancelPost');

    createPostButton.addEventListener('click', function () {
        createPostForm.style.display = 'block';
        createPostButton.style.display = 'none';
    });

    function hidePostFormAndShowButton() {
        createPostForm.style.display = 'none';
        createPostButton.style.display = 'block';
    }

    if (cancelPostButton) {
        cancelPostButton.addEventListener('click', function () {
            createPostForm.style.display = 'none';
            hidePostFormAndShowButton();
        });
    }

    document.getElementById('submitPost').addEventListener('click', function (e) {
        e.preventDefault();
        hidePostFormAndShowButton();
        const title = document.getElementById('postTitle').value;
        const content = document.getElementById('postContent').value;
        const user = JSON.parse(document.getElementById('userData').getAttribute('data-user'));

        fetch('/posts/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ title, content, author: user.username, votes: 0 }),
        })
            .then(response => response.json())
            .then(post => {
                const postsContainer = document.querySelector('.posts-section');
                postsContainer.insertAdjacentHTML('afterbegin', `<div class="post"><h3>${post.title}</h3><p>${post.content}</p><p>Author: ${post.author}</p><p>Votes: ${post.votes}</p></div>`);
                document.getElementById('postTitle').value = '';
                document.getElementById('postContent').value = '';
                createPostForm.style.display = 'none';
            })
            .catch(error => console.error('Error:', error));
    });

    function loadAndDisplayPosts() {
        fetch('/posts/')
            .then(response => response.json())
            .then(data => {
                const postsContainer = document.querySelector('.posts-section');
                data.posts.forEach(post => {
                    postsContainer.insertAdjacentHTML('afterbegin', `<div class="post"><h3>${post.title}</h3><p>${post.content}</p><p>Author: ${post.author}</p><p>Votes: ${post.votes}</p></div>`);
                });
            })
            .catch(error => console.error('Error loading posts:', error));
    }

    loadAndDisplayPosts(); // Call the function to load posts
});
