<template>
  <div class="register-container">
    <el-card class="register-card">
      <h2>Register</h2>
      <el-form
          ref="registerFormRef"
          :model="registerForm"
          :rules="rules"
          label-width="120px"
      >
        <el-form-item label="Username" prop="username">
          <el-input v-model="registerForm.username" />
        </el-form-item>

        <el-form-item label="Email" prop="email">
          <el-input v-model="registerForm.email" />
        </el-form-item>

        <el-form-item label="Password" prop="password">
          <el-input
              v-model="registerForm.password"
              type="password"
          />
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="handleRegister">Register</el-button>
        </el-form-item>
      </el-form>

      <div class="login-link">
        Already have an account?
        <router-link to="/login">Login now</router-link>
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
const registerFormRef = ref(null)

// 使用 reactive 定义表单数据
const registerForm = reactive({
  username: '',
  email: '',
  password: ''
})

// 表单验证规则
const rules = {
  username: [
    { required: true, message: 'Please input username', trigger: 'blur' },
    { min: 3, max: 20, message: 'Length should be 3 to 20 characters', trigger: 'blur' }
  ],
  email: [
    { required: true, message: 'Please input email', trigger: 'blur' },
    { type: 'email', message: 'Please input valid email address', trigger: 'blur' }
  ],
  password: [
    { required: true, message: 'Please input password', trigger: 'blur' },
    { min: 6, message: 'Password must be at least 6 characters', trigger: 'blur' }
  ]
}

const handleRegister = async () => {
  if (!registerFormRef.value) return

  try {
    await registerFormRef.value.validate()
    await userStore.register(registerForm)
    ElMessage.success('Registration successful!')
    router.push('/login')
  } catch (error) {
    ElMessage.error(error.message || 'Registration failed')
  }
}
</script>

<style scoped>
.register-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: calc(100vh - 60px);
  padding: 20px;
}

.register-card {
  width: 100%;
  max-width: 500px;
}

.login-link {
  text-align: center;
  margin-top: 20px;
}

h2 {
  text-align: center;
  margin-bottom: 30px;
}
</style>