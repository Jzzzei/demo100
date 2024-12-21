<template>
  <div class="orders">
    <h1>My Orders</h1>
    
    <div v-if="loading" class="loading">
      <el-loading :fullscreen="true" />
    </div>
    
    <div v-else-if="orders.length === 0" class="empty-orders">
      <el-empty description="No orders yet">
        <el-button type="primary" @click="$router.push('/products')">
          Start Shopping
        </el-button>
      </el-empty>
    </div>
    
    <template v-else>
      <el-card v-for="order in orders" :key="order.id" class="order-card">
        <div class="order-header">
          <div class="order-info">
            <h3>Order #{{ order.id }}</h3>
            <p>{{ formatDate(order.orderDate) }}</p>
          </div>
          <div class="order-status">
            <el-tag :type="getStatusType(order.status)">
              {{ order.status }}
            </el-tag>
          </div>
        </div>
        
        <el-table :data="order.orderItems" style="width: 100%">
          <el-table-column label="Product" width="400">
            <template #default="{ row }">
              <div class="product-info">
                <img :src="row.product.imageUrl || 'https://via.placeholder.com/100'" class="product-image">
                <div class="product-details">
                  <h4>{{ row.product.name }}</h4>
                  <p class="category">{{ row.product.category }}</p>
                </div>
              </div>
            </template>
          </el-table-column>
          
          <el-table-column label="Price" width="150">
            <template #default="{ row }">
              $ {{ row.price }}
            </template>
          </el-table-column>
          
          <el-table-column label="Quantity" width="150">
            <template #default="{ row }">
              {{ row.quantity }}
            </template>
          </el-table-column>
          
          <el-table-column label="Subtotal" width="150">
            <template #default="{ row }">
              $ {{ (row.price * row.quantity).toFixed(2) }}
            </template>
          </el-table-column>
        </el-table>
        
        <div class="order-footer">
          <div class="shipping-info">
            <p><strong>Shipping Address:</strong> {{ order.shippingAddress }}</p>
            <p><strong>Payment Method:</strong> {{ order.paymentMethod }}</p>
          </div>
          <div class="total-amount">
            <h3>Total: $ {{ order.totalAmount }}</h3>
          </div>
          <div class="actions">
            <el-button 
              v-if="order.status === 'PENDING'"
              type="primary"
              @click="confirmOrder(order.id)">
              Confirm Order
            </el-button>
            <el-button 
              v-if="['PENDING', 'PAID'].includes(order.status)"
              type="danger"
              @click="cancelOrder(order.id)">
              Cancel Order
            </el-button>
          </div>
        </div>
      </el-card>
    </template>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

const orders = ref([])
const loading = ref(false)

const loadOrders = async () => {
  try {
    loading.value = true
    const response = await axios.get('/api/orders')
    orders.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load orders')
  } finally {
    loading.value = false
  }
}

const confirmOrder = async (orderId) => {
  try {
    await ElMessageBox.confirm('Are you sure you want to confirm this order?')
    await axios.post(`/api/orders/${orderId}/confirm`)
    ElMessage.success('Order confirmed')
    loadOrders()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to confirm order')
    }
  }
}

const cancelOrder = async (orderId) => {
  try {
    await ElMessageBox.confirm(
      'Are you sure you want to cancel this order?',
      'Warning',
      {
        confirmButtonText: 'Yes',
        cancelButtonText: 'No',
        type: 'warning'
      }
    )
    await axios.post(`/api/orders/${orderId}/cancel`)
    ElMessage.success('Order cancelled')
    loadOrders()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to cancel order')
    }
  }
}

const formatDate = (date) => {
  return new Date(date).toLocaleString()
}

const getStatusType = (status) => {
  const types = {
    'PENDING': 'warning',
    'PAID': 'success',
    'SHIPPED': 'primary',
    'DELIVERED': 'success',
    'CANCELLED': 'danger'
  }
  return types[status] || 'info'
}

onMounted(() => {
  loadOrders()
})
</script>

<style scoped>
.orders {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.orders h1 {
  margin-bottom: 30px;
  color: #2c3e50;
}

.order-card {
  margin-bottom: 30px;
}

.order-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.order-info h3 {
  margin: 0;
  color: #409EFF;
}

.order-info p {
  margin: 5px 0 0 0;
  color: #666;
}

.product-info {
  display: flex;
  align-items: center;
  gap: 20px;
}

.product-image {
  width: 80px;
  height: 80px;
  object-fit: cover;
  border-radius: 4px;
}

.product-details h4 {
  margin: 0 0 5px 0;
}

.category {
  color: #666;
  margin: 0;
}

.order-footer {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.shipping-info p {
  margin: 5px 0;
}

.total-amount {
  text-align: right;
}

.total-amount h3 {
  color: #409EFF;
  margin: 0;
}

.actions {
  display: flex;
  gap: 10px;
  margin-top: 10px;
}

.empty-orders {
  text-align: center;
  padding: 40px;
}
</style> 