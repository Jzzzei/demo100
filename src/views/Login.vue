<template>
  <div class="login-container">
    <el-card class="login-card">
      <h2>Login</h2>
      <el-form 
        ref="loginFormRef"
        :model="loginForm"
        :rules="rules"
        label-width="120px"
      >
        <el-form-item label="Username" prop="username">
          <el-input v-model="loginForm.username" />
        </el-form-item>
        
        <el-form-item label="Password" prop="password">
          <el-input 
            v-model="loginForm.password" 
            type="password" 
          />
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" @click="handleLogin">Login</el-button>
        </el-form-item>
      </el-form>
      
      <div class="register-link">
        Don't have an account? 
        <router-link to="/register">Register now</router-link>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useUserStore } from '../stores/user'

const router = useRouter()
const userStore = useUserStore()
const loginFormRef = ref(null)

// 使用 reactive 定义表单数据
const loginForm = reactive({
  username: '',
  password: ''
})

// 表单验证规则
const rules = {
  username: [
    { required: true, message: 'Please input username', trigger: 'blur' }
  ],
  password: [
    { required: true, message: 'Please input password', trigger: 'blur' }
  ]
}

const handleLogin = async () => {
  if (!loginFormRef.value) return
  
  try {
    await loginFormRef.value.validate()
    await userStore.login(loginForm)
    ElMessage.success('Login successful!')
    router.push('/')
  } catch (error) {
    ElMessage.error(error.message || 'Login failed')
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: calc(100vh - 60px);
  padding: 20px;
}

.login-card {
  width: 100%;
  max-width: 500px;
}

.register-link {
  text-align: center;
  margin-top: 20px;
}

h2 {
  text-align: center;
  margin-bottom: 30px;
}
</style>