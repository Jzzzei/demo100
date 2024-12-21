<template>
  <div class="cart">
    <h1>Shopping Cart</h1>
    
    <div v-if="cartItems.length === 0" class="empty-cart">
      <el-empty description="Your cart is empty">
        <el-button type="primary" @click="$router.push('/products')">
          Continue Shopping
        </el-button>
      </el-empty>
    </div>
    
    <template v-else>
      <div class="cart-items">
        <el-table :data="cartItems" style="width: 100%">
          <el-table-column label="Product" width="400">
            <template #default="{ row }">
              <div class="product-info">
                <img :src="row.product.imageUrl || 'https://via.placeholder.com/100'" class="product-image">
                <div class="product-details">
                  <h3>{{ row.product.name }}</h3>
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
          
          <el-table-column label="Quantity" width="200">
            <template #default="{ row }">
              <el-input-number 
                v-model="row.quantity" 
                :min="1" 
                :max="row.product.stock"
                @change="updateQuantity(row)">
              </el-input-number>
            </template>
          </el-table-column>
          
          <el-table-column label="Total" width="150">
            <template #default="{ row }">
              $ {{ (row.price * row.quantity).toFixed(2) }}
            </template>
          </el-table-column>
          
          <el-table-column label="Actions">
            <template #default="{ row }">
              <el-button 
                type="danger" 
                size="small" 
                @click="removeItem(row.id)">
                Remove
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
      
      <div class="cart-summary">
        <div class="summary-details">
          <div class="summary-row">
            <span>Subtotal:</span>
            <span>$ {{ subtotal.toFixed(2) }}</span>
          </div>
          <div class="summary-row">
            <span>Shipping:</span>
            <span>$ {{ shipping.toFixed(2) }}</span>
          </div>
          <div class="summary-row total">
            <span>Total:</span>
            <span>$ {{ total.toFixed(2) }}</span>
          </div>
        </div>
        
        <div class="actions">
          <el-button @click="$router.push('/products')">
            Continue Shopping
          </el-button>
          <el-button type="primary" @click="checkout">
            Proceed to Checkout
          </el-button>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

const router = useRouter()
const cartItems = ref([])
const loading = ref(false)

const subtotal = computed(() => {
  return cartItems.value.reduce((sum, item) => {
    return sum + (item.price * item.quantity)
  }, 0)
})

const shipping = computed(() => {
  return subtotal.value > 100 ? 0 : 10
})

const total = computed(() => {
  return subtotal.value + shipping.value
})

const loadCartItems = async () => {
  try {
    loading.value = true
    const response = await axios.get('/api/cart')
    cartItems.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load cart items')
  } finally {
    loading.value = false
  }
}

const updateQuantity = async (item) => {
  try {
    await axios.put(`/api/cart/${item.id}`, {
      productId: item.product.id,
      quantity: item.quantity
    })
    ElMessage.success('Cart updated')
  } catch (error) {
    ElMessage.error('Failed to update cart')
    loadCartItems() // Reload cart items to restore original state
  }
}

const removeItem = async (itemId) => {
  try {
    await ElMessageBox.confirm(
      'Are you sure you want to remove this item?',
      'Warning',
      {
        confirmButtonText: 'Yes',
        cancelButtonText: 'No',
        type: 'warning'
      }
    )
    
    await axios.delete(`/api/cart/${itemId}`)
    ElMessage.success('Item removed from cart')
    loadCartItems()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to remove item')
    }
  }
}

const checkout = () => {
  router.push('/checkout')
}

onMounted(() => {
  loadCartItems()
})
</script>

<style scoped>
.cart {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.cart h1 {
  margin-bottom: 30px;
  color: #2c3e50;
}

.empty-cart {
  text-align: center;
  padding: 40px;
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

.product-details h3 {
  margin: 0 0 5px 0;
  font-size: 1.1em;
}

.category {
  color: #666;
  margin: 0;
}

.cart-summary {
  margin-top: 30px;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
}

.summary-details {
  margin-bottom: 20px;
}

.summary-row {
  display: flex;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid #eee;
}

.summary-row.total {
  font-size: 1.2em;
  font-weight: bold;
  border-bottom: none;
  padding-top: 20px;
}

.actions {
  display: flex;
  justify-content: space-between;
  margin-top: 20px;
}
</style> 