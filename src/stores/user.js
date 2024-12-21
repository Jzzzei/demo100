import { defineStore } from 'pinia'
import api from '../api'

export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    token: localStorage.getItem('token') || null,
  }),

  getters: {
    isLoggedIn: (state) => !!state.token,
  },

  actions: {
    async register(userData) {
      try {
        const response = await api.post('/auth/register', userData)
        return response
      } catch (error) {
        console.error('Store register error:', error)
        throw {
          message: error?.response?.data?.message || error?.message || 'Registration failed',
          status: error?.response?.status
        }
      }
    },

    async login(credentials) {
      try {
        const response = await api.post('/auth/login', credentials)
        
        if (response.token && response.user) {
          this.token = response.token
          this.user = response.user
          localStorage.setItem('token', response.token)
          api.defaults.headers.common['Authorization'] = `Bearer ${response.token}`
        } else {
          throw new Error('Invalid response format')
        }
        
        return response
      } catch (error) {
        console.error('Store login error:', error)
        throw {
          message: error?.response?.data?.message || error?.message || 'Login failed',
          status: error?.response?.status
        }
      }
    },

    logout() {
      this.user = null
      this.token = null
      localStorage.removeItem('token')
      delete api.defaults.headers.common['Authorization']
    }
  }
})