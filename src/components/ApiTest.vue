<template>
  <div class="api-test">
    <h2>API 测试面板</h2>
    
    <!-- 注册测试 -->
    <el-card class="test-card">
      <h3>注册测试</h3>
      <el-form :model="registerForm" label-width="100px">
        <el-form-item label="用户名">
          <el-input v-model="registerForm.username"></el-input>
        </el-form-item>
        <el-form-item label="邮箱">
          <el-input v-model="registerForm.email"></el-input>
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="registerForm.password" type="password"></el-input>
        </el-form-item>
        <el-button type="primary" @click="testRegister">测试注册</el-button>
      </el-form>
    </el-card>
    
    <!-- 登录测试 -->
    <el-card class="test-card">
      <h3>登录测试</h3>
      <el-form :model="loginForm" label-width="100px">
        <el-form-item label="用户名">
          <el-input v-model="loginForm.username"></el-input>
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="loginForm.password" type="password"></el-input>
        </el-form-item>
        <el-button type="primary" @click="testLogin">测试登录</el-button>
      </el-form>
    </el-card>
    
    <!-- 产品API测试 -->
    <el-card class="test-card">
      <h3>产品API测试</h3>
      <el-button @click="testGetProducts">获取产品列表</el-button>
      <el-button @click="testSearchProducts">搜索产品</el-button>
    </el-card>
    
    <!-- 购物车测试 -->
    <el-card class="test-card">
      <h3>购物车测试</h3>
      <el-form :model="cartForm" label-width="100px">
        <el-form-item label="商品ID">
          <el-input v-model="cartForm.productId" type="number"></el-input>
        </el-form-item>
        <el-form-item label="数量">
          <el-input v-model="cartForm.quantity" type="number"></el-input>
        </el-form-item>
      </el-form>
      <el-button @click="testAddToCart">添加到购物车</el-button>
      <el-button @click="testGetCart">获取购物车</el-button>
    </el-card>
    
    <!-- 订单测试 -->
    <el-card class="test-card">
      <h3>订单测试</h3>
      <el-button @click="testCreateOrder">创建订单</el-button>
      <el-button @click="testGetOrders">获取订单列表</el-button>
    </el-card>
    
    <!-- 响应结果展示 -->
    <el-card class="test-card">
      <h3>测试结果</h3>
      <pre>{{ testResult }}</pre>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useUserStore } from '../stores/user'
import api from '../api'
import { ElMessage } from 'element-plus'

const userStore = useUserStore()
const testResult = ref('')

// 注册表单
const registerForm = ref({
  username: 'testuser',
  email: 'test@example.com',
  password: 'password123'
})

// 登录表单
const loginForm = ref({
  username: 'testuser',
  password: 'password123'
})

// 购物车表单
const cartForm = ref({
  productId: 1,
  quantity: 1
})

// 测试注册
const testRegister = async () => {
  try {
    const response = await api.post('/auth/register', registerForm.value)
    testResult.value = JSON.stringify(response, null, 2)
    ElMessage.success('注册成功')
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('注册失败')
  }
}

// 测试登录
const testLogin = async () => {
  try {
    await userStore.login(loginForm.value)
    testResult.value = JSON.stringify({
      isLoggedIn: userStore.isLoggedIn,
      user: userStore.user
    }, null, 2)
    ElMessage.success('登录成功')
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('登录失败')
  }
}

// 测试获取产品列表
const testGetProducts = async () => {
  try {
    const response = await api.get('/products', {
      headers: {
        'Accept': 'application/json'
      }
    })
    console.log('Response headers:', response.headers)
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('获取产品列表失败')
  }
}

// 测试搜索产品
const testSearchProducts = async () => {
  try {
    const response = await api.get('/products/search', {
      params: { keyword: 'test' }
    })
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('搜索产品失败')
  }
}

// 购物车测试方法
const testAddToCart = async () => {
  try {
    const response = await api.post('/cart/add', cartForm.value)
    testResult.value = JSON.stringify(response, null, 2)
    ElMessage.success('添加成功')
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('添加失败')
  }
}

const testGetCart = async () => {
  try {
    const response = await api.get('/cart')
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('获取购物车失败')
  }
}

// 订单测试方法
const testCreateOrder = async () => {
  try {
    const response = await api.post('/orders', {
      shippingAddress: "测试地址",
      paymentMethod: "CREDIT_CARD"
    })
    testResult.value = JSON.stringify(response, null, 2)
    ElMessage.success('订单创建成功')
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('订单创建失败')
  }
}

const testGetOrders = async () => {
  try {
    const response = await api.get('/orders')
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = JSON.stringify(error.response?.data || error.message, null, 2)
    ElMessage.error('获取订单列表失败')
  }
}
</script>

<style scoped>
.api-test {
  max-width: 800px;
  margin: 20px auto;
  padding: 20px;
}

.test-card {
  margin-bottom: 20px;
  padding: 20px;
}

h3 {
  margin-bottom: 20px;
}

pre {
  background: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
}

.el-button {
  margin-right: 10px;
}
</style>
  