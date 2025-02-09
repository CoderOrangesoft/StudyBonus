const apiHost = 'http://localhost:64015'; // 设置API主机地址
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('loginForm')) {
        document.getElementById('loginForm').addEventListener('submit', async(e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const response = await fetch(`${apiHost}/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            if (response.ok) {
                window.location.href = 'index.html';
            } else {
                alert(data.message);
            }
        });
    }

    if (document.getElementById('registerForm')) {
        document.getElementById('registerForm').addEventListener('submit', async(e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const response = await fetch(`${apiHost}/api/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            if (response.ok) {
                alert('注册成功');
                window.location.href = 'login.html';
            } else {
                alert(data.message);
            }
        });
    }

    if (document.getElementById('randomQuestion')) {
        document.getElementById('randomQuestion').addEventListener('click', async() => {
            const response = await fetch(`${apiHost}/api/study/random_question_from_all`, {
                method: 'GET',
                credentials: 'include'
            });
            const data = await response.json();
            const hideSource = document.getElementById('hideSource').checked;
            if (hideSource) {
                document.getElementById('questionResult').innerHTML = `问题: ${data.message}  <font id="questionSource" style="color:gray;display:none">来自单元: ${data.from_unit}</font>`;
            } else {
                document.getElementById('questionResult').innerHTML = `问题: ${data.message}  <font id="questionSource" style="color:gray;display:inline">来自单元: ${data.from_unit}</font>`;
            }
        });
    }

    if (document.getElementById('randomQuestionByUnit')) {
        getUnits();
        document.getElementById('randomQuestionByUnit').addEventListener('click', async() => {
            if (document.getElementById('unitSelect').value != '0') {
                let unit_id = document.getElementById('unitSelect').value;
                console.log(unit_id);
                const response = await fetch(`${apiHost}/api/study/random_question_from_unit?unit=${unit_id}`, {
                    method: 'GET',
                    credentials: 'include'
                });
                const data = await response.json();
                const hideSource = document.getElementById('hideSource').checked;
                if (hideSource) {
                    document.getElementById('questionResult').innerHTML = `问题: ${data.message}  <font id="questionSource" style="color:gray;display:none">来自单元: ${data.from_unit}</font>`;
                } else {
                    document.getElementById('questionResult').innerHTML = `问题: ${data.message}  <font id="questionSource" style="color:gray;display:inline">来自单元: ${data.from_unit}</font>`;
                }
            }
        });
    }

    if (document.getElementById('completeTask')) {
        document.getElementById('completeTask').addEventListener('click', async() => {
            const response = await fetch(`${apiHost}/api/study/task`, {
                method: 'POST',
                credentials: 'include'
            });
            const data = await response.json();
            document.getElementById('taskResult').innerText = data.message;
        });
    }

    if (document.getElementById('infoResult')) {
        const urlParams = new URLSearchParams(window.location.search);
        const userId = urlParams.get('userid');
        const endpoint = userId ? `/api/account/others_info?id=${userId}` : '/api/account/info';
        fetch(`${apiHost}${endpoint}`, {
                method: 'GET',
                credentials: 'include'
            }).then(response => response.json())
            .then(data => {
                const resultContainer = document.getElementById('infoResult');
                resultContainer.innerHTML = ''; // 清空之前的内容

                if (data.message) {
                    const ul = document.createElement('ul');

                    Object.keys(data.message).forEach(key => {
                        const li = document.createElement('li');
                        li.innerHTML = `${key}: ${data.message[key]}`;
                        ul.appendChild(li);
                    });

                    resultContainer.appendChild(ul);
                } else {
                    resultContainer.innerText = '没有数据返回！';
                }
            })
            .catch(error => {
                const resultContainer = document.getElementById('infoResult');
                resultContainer.innerText = '请求失败，请稍后重试。';
            });

    }

    if (document.getElementById('resetPasswordForm')) {
        document.getElementById('resetPasswordForm').addEventListener('submit', async(e) => {
            e.preventDefault();
            const newPassword = document.getElementById('newPassword').value;
            const response = await fetch(`${apiHost}/api/account/password_reset`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ newPassword })
            });
            const data = await response.json();
            if (response.ok) {
                alert('密码重置成功');
            } else {
                alert(data.message);
            }
        });
    }
});

function changeSourceDisplayMode() {
    if (document.getElementById('hideSource').checked) {
        document.getElementById('questionSource').style.display = 'none';
    } else {
        document.getElementById('questionSource').style.display = 'inline';
    }
}

async function getUnits() {
    try {
        let response = await fetch(`${apiHost}/api/study/get_unit_list`, {
            method: 'GET',
            credentials: 'include'
        });

        let data = await response.json(); // 等待解析 JSON
        let data_getUnits = data['message']; // 获取 'message' 数据
        let unitSelecter = document.getElementById('unitSelect');

        // 确保 data_getUnits 是一个对象并迭代它
        for (let unitName = 0; unitName <= data_getUnits.length; unitName++) {
            if (data_getUnits.hasOwnProperty(unitName)) {
                let option = document.createElement('option');
                option.value = unitName + 1;
                option.innerText = data_getUnits[unitName];
                unitSelecter.appendChild(option);
            }
        }
    } catch (error) {
        console.error('Error fetching unit list:', error);
    }
}