const loadData = async () => {
    const data = await fetchData()
    if (!data) {
        console.log("data is not valid " + data)
        setForm(true)
    } else {
        console.log("data is valid " + data)
        setForm(false)
        setData(data)
    }
}

const setForm = (visible) => {
    document.getElementById("form-placeholder").style.display = visible ? "block" : "none"
    document.getElementById("logout-button").style.display = visible ? "none" : "block" 
}

const setData = (data) => {
    const placeholder = document.getElementById("data-placeholder")
    const roles = data.roles.map(role => `<li class="list-group-item">${role}</li>`).join("")
    placeholder.innerHTML = `<div><h4>${data.username.toUpperCase()}, you have the following roles</h4><div><ul class="list-group">${roles}</ul></div></div>`
}

const fetchData = async() => {
    const response = await fetch("/api/data", {
        headers: {
          "Content-Type": "application/json",
        },
        method: "GET",
    });
    
    if (response.status === 401) {
        return Promise.resolve(false)
    }

    if (!response.ok) {      
        alert("get data failed!")
        return Promise.resolve(false)
    }

    return await response.json()
}


const login = async (e) => {
    e.preventDefault();
    const form = document.querySelector('form');
    const data = Object.fromEntries(new FormData(form).entries())
    await postLogin(data.username, data.password)    
    location.reload()
}

const logout = async (e) => {
    e.preventDefault();
    await issueLogout()
    location.reload()
}

const postLogin = async(username, password) => {
    const formData = new URLSearchParams()
    formData.append("username", username)
    formData.append("password", password)
  
    const response = await fetch("/login", {
      body: formData,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        credentials: "include",
      },
      method: "POST",
    });
  
    if (!response.ok) {      
      alert("login failed!")
      return
    }
}

const issueLogout = async() => {
    const response = await fetch("/logout", {
      headers: {
        credentials: "include",
      },
      method: "GET",
    });
    
    if (!response.ok) {      
       alert("logout failed!")
       return
    }
}