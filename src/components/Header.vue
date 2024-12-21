<template>
  <div class="header">
    <div class="logo">
      <router-link to="/">E-Shop</router-link>
    </div>
    <el-menu mode="horizontal" :router="true" class="nav-menu">
      <el-menu-item index="/products">
        <el-icon><Shop /></el-icon>
        Products
      </el-menu-item>
      <el-menu-item v-if="isLoggedIn" index="/cart">
        <el-icon><ShoppingCart /></el-icon>
        Cart
      </el-menu-item>
      <el-menu-item v-if="isLoggedIn" index="/orders">
        <el-icon><List /></el-icon>
        Orders
      </el-menu-item>
      <el-menu-item v-if="isAdmin" index="/admin">
        <el-icon><Setting /></el-icon>
        Admin
      </el-menu-item>
    </el-menu>
    <div class="user-area">
      <template v-if="isLoggedIn">
        <el-dropdown>
          <span class="user-profile">
            {{ username }}
            <el-icon><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item @click="goToProfile">个人中心</el-dropdown-item>
              <el-dropdown-item @click="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </template>
      <template v-else>
        <el-button @click="$router.push('/login')">登录</el-button>
        <el-button type="primary" @click="$router.push('/register')">注册</el-button>
      </template>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useUserStore } from '../stores/user'
import { Shop, ShoppingCart, List, Setting, ArrowDown } from '@element-plus/icons-vue'

const router = useRouter()
const userStore = useUserStore()

const isLoggedIn = computed(() => userStore.isLoggedIn)
const username = computed(() => userStore.username)
const isAdmin = computed(() => userStore.isAdmin)

const goToProfile = () => {
  router.push('/profile')
}

const logout = () => {
  userStore.logout()
  router.push('/login')
}
</script>

<style scoped>
.header {
  display: flex;
  align-items: center;
  padding: 0 20px;
  height: 60px;
  background-color: white;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.logo {
  font-size: 24px;
  font-weight: bold;
  margin-right: 40px;
}

.logo a {
  text-decoration: none;
  color: #409EFF;
}

.nav-menu {
  flex-grow: 1;
  border-bottom: none;
}

.user-area {
  display: flex;
  gap: 10px;
  align-items: center;
}

.user-profile {
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 5px;
}
</style>