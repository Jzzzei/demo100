<template>
  <div class="checkout">
    <h1>Checkout</h1>
    
    <el-steps :active="currentStep" finish-status="success" class="steps">
      <el-step title="Review Cart"></el-step>
      <el-step title="Shipping"></el-step>
      <el-step title="Payment"></el-step>
      <el-step title="Confirm"></el-step>
    </el-steps>
    
    <!-- Step 1: Review Cart -->
    <div v-if="currentStep === 0" class="step-content">
      <el-table :data="cartItems" style="width: 100%">
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
      
      <div class="summary">
        <h3>Order Summary</h3>
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
    </div>
    
    <!-- Step 2: Shipping -->
    <div v-if="currentStep === 1" class="step-content">
      <div class="address-selection">
        <h3>Select Shipping Address</h3>
        <el-radio-group v-model="selectedAddress">
          <el-radio v-for="address in addresses" :key="address.id" :label="address.id" class="address-option">
            <div class="address-details">
              <p><strong>Street:</strong> {{ address.street }}</p>
              <p><strong>City:</strong> {{ address.city }}</p>
              <p><strong>State:</strong> {{ address.state }}</p>
              <p><strong>Country:</strong> {{ address.country }}</p>
              <p><strong>Zip Code:</strong> {{ address.zipCode }}</p>
              <el-tag v-if="address.isDefault" type="success">Default</el-tag>
            </div>
          </el-radio>
        </el-radio-group>
        
        <el-button type="primary" @click="showAddressDialog = true" class="add-button">
          Add New Address
        </el-button>
      </div>
    </div>
    
    <!-- Step 3: Payment -->
    <div v-if="currentStep === 2" class="step-content">
      <div class="payment-selection">
        <h3>Select Payment Method</h3>
        <el-radio-group v-model="selectedPayment">
          <el-radio v-for="card in creditCards" :key="card.id" :label="card.id" class="payment-option">
            <div class="card-details">
              <p><strong>Card Number:</strong> **** **** **** {{ card.cardNumber.slice(-4) }}</p>
              <p><strong>Card Holder:</strong> {{ card.cardHolderName }}</p>
              <p><strong>Expires:</strong> {{ card.expirationMonth }}/{{ card.expirationYear }}</p>
              <el-tag v-if="card.isDefault" type="success">Default</el-tag>
            </div>
          </el-radio>
        </el-radio-group>
        
        <el-button type="primary" @click="showCardDialog = true" class="add-button">
          Add New Card
        </el-button>
      </div>
    </div>
    
    <!-- Step 4: Confirm -->
    <div v-if="currentStep === 3" class="step-content">
      <div class="order-confirmation">
        <h3>Order Summary</h3>
        <div class="confirmation-details">
          <div class="shipping-info">
            <h4>Shipping Address</h4>
            <p>{{ selectedAddressDetails?.street }}</p>
            <p>{{ selectedAddressDetails?.city }}, {{ selectedAddressDetails?.state }}</p>
            <p>{{ selectedAddressDetails?.country }}, {{ selectedAddressDetails?.zipCode }}</p>
          </div>
          
          <div class="payment-info">
            <h4>Payment Method</h4>
            <p>Card ending in {{ selectedPaymentDetails?.cardNumber.slice(-4) }}</p>
            <p>{{ selectedPaymentDetails?.cardHolderName }}</p>
          </div>
          
          <div class="final-summary">
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
        </div>
      </div>
    </div>
    
    <!-- Navigation Buttons -->
    <div class="step-actions">
      <el-button v-if="currentStep > 0" @click="currentStep--">Previous</el-button>
      <el-button 
        v-if="currentStep < 3" 
        type="primary" 
        @click="nextStep"
        :disabled="!canProceed">
        Next
      </el-button>
      <el-button 
        v-else 
        type="primary" 
        @click="placeOrder"
        :loading="loading">
        Place Order
      </el-button>
    </div>
    
    <!-- Address Dialog -->
    <el-dialog 
      title="Add New Address"
      v-model="showAddressDialog"
      width="500px">
      <el-form :model="newAddress" label-width="120px">
        <el-form-item label="Street">
          <el-input v-model="newAddress.street"></el-input>
        </el-form-item>
        <el-form-item label="City">
          <el-input v-model="newAddress.city"></el-input>
        </el-form-item>
        <el-form-item label="State">
          <el-input v-model="newAddress.state"></el-input>
        </el-form-item>
        <el-form-item label="Country">
          <el-input v-model="newAddress.country"></el-input>
        </el-form-item>
        <el-form-item label="Zip Code">
          <el-input v-model="newAddress.zipCode"></el-input>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="newAddress.isDefault">Set as default address</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddressDialog = false">Cancel</el-button>
        <el-button type="primary" @click="saveAddress">Save</el-button>
      </template>
    </el-dialog>
    
    <!-- Card Dialog -->
    <el-dialog 
      title="Add New Card"
      v-model="showCardDialog"
      width="500px">
      <el-form :model="newCard" label-width="120px">
        <el-form-item label="Card Number">
          <el-input v-model="newCard.cardNumber"></el-input>
        </el-form-item>
        <el-form-item label="Card Holder">
          <el-input v-model="newCard.cardHolderName"></el-input>
        </el-form-item>
        <el-form-item label="Expiration">
          <el-row :gutter="10">
            <el-col :span="12">
              <el-select v-model="newCard.expirationMonth" placeholder="Month">
                <el-option 
                  v-for="month in 12" 
                  :key="month"
                  :label="String(month).padStart(2, '0')"
                  :value="month">
                </el-option>
              </el-select>
            </el-col>
            <el-col :span="12">
              <el-select v-model="newCard.expirationYear" placeholder="Year">
                <el-option 
                  v-for="year in 10" 
                  :key="year"
                  :label="currentYear + year"
                  :value="currentYear + year">
                </el-option>
              </el-select>
            </el-col>
          </el-row>
        </el-form-item>
        <el-form-item label="CVV">
          <el-input v-model="newCard.cvv" maxlength="4"></el-input>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="newCard.isDefault">Set as default card</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCardDialog = false">Cancel</el-button>
        <el-button type="primary" @click="saveCard">Save</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import axios from 'axios'

const router = useRouter()
const currentStep = ref(0)
const loading = ref(false)
const cartItems = ref([])
const addresses = ref([])
const creditCards = ref([])
const selectedAddress = ref(null)
const selectedPayment = ref(null)
const currentYear = new Date().getFullYear()

// Dialog controls
const showAddressDialog = ref(false)
const showCardDialog = ref(false)

// Form models
const newAddress = ref({
  street: '',
  city: '',
  state: '',
  country: '',
  zipCode: '',
  isDefault: false
})

const newCard = ref({
  cardNumber: '',
  cardHolderName: '',
  expirationMonth: null,
  expirationYear: null,
  cvv: '',
  isDefault: false
})

// Computed properties
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

const selectedAddressDetails = computed(() => {
  return addresses.value.find(addr => addr.id === selectedAddress.value)
})

const selectedPaymentDetails = computed(() => {
  return creditCards.value.find(card => card.id === selectedPayment.value)
})

const canProceed = computed(() => {
  switch (currentStep.value) {
    case 0:
      return cartItems.value.length > 0
    case 1:
      return selectedAddress.value != null
    case 2:
      return selectedPayment.value != null
    default:
      return true
  }
})

// Methods
const loadCartItems = async () => {
  try {
    const response = await axios.get('/api/cart')
    cartItems.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load cart items')
  }
}

const loadAddresses = async () => {
  try {
    const response = await axios.get('/api/profile/addresses')
    addresses.value = response.data
    if (addresses.value.length > 0) {
      const defaultAddress = addresses.value.find(addr => addr.isDefault)
      selectedAddress.value = defaultAddress?.id || addresses.value[0].id
    }
  } catch (error) {
    ElMessage.error('Failed to load addresses')
  }
}

const loadCreditCards = async () => {
  try {
    const response = await axios.get('/api/profile/credit-cards')
    creditCards.value = response.data
    if (creditCards.value.length > 0) {
      const defaultCard = creditCards.value.find(card => card.isDefault)
      selectedPayment.value = defaultCard?.id || creditCards.value[0].id
    }
  } catch (error) {
    ElMessage.error('Failed to load payment methods')
  }
}

const nextStep = () => {
  if (canProceed.value) {
    currentStep.value++
  }
}

const saveAddress = async () => {
  try {
    const response = await axios.post('/api/profile/addresses', newAddress.value)
    addresses.value.push(response.data)
    selectedAddress.value = response.data.id
    showAddressDialog.value = false
    ElMessage.success('Address saved successfully')
  } catch (error) {
    ElMessage.error('Failed to save address')
  }
}

const saveCard = async () => {
  try {
    const response = await axios.post('/api/profile/credit-cards', newCard.value)
    creditCards.value.push(response.data)
    selectedPayment.value = response.data.id
    showCardDialog.value = false
    ElMessage.success('Card saved successfully')
  } catch (error) {
    ElMessage.error('Failed to save card')
  }
}

const placeOrder = async () => {
  try {
    loading.value = true
    const orderData = {
      shippingAddress: selectedAddressDetails.value.street + ', ' +
        selectedAddressDetails.value.city + ', ' +
        selectedAddressDetails.value.state + ', ' +
        selectedAddressDetails.value.country + ' ' +
        selectedAddressDetails.value.zipCode,
      paymentMethod: 'CREDIT_CARD'
    }
    
    const orderResponse = await axios.post('/api/orders', orderData)
    await axios.post('/api/payments/process', {
      orderId: orderResponse.data.id,
      paymentMethod: 'CREDIT_CARD'
    })
    
    ElMessage.success('Order placed successfully')
    router.push('/orders')
  } catch (error) {
    ElMessage.error(error.response?.data?.error || 'Failed to place order')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadCartItems()
  loadAddresses()
  loadCreditCards()
})
</script>

<style scoped>
.checkout {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.steps {
  margin: 40px 0;
}

.step-content {
  margin: 30px 0;
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

.summary {
  margin-top: 30px;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
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

.address-option, .payment-option {
  display: block;
  margin-bottom: 20px;
  padding: 15px;
  border: 1px solid #eee;
  border-radius: 4px;
}

.address-details p, .card-details p {
  margin: 5px 0;
}

.add-button {
  margin-top: 20px;
}

.step-actions {
  margin-top: 30px;
  display: flex;
  justify-content: space-between;
}

.confirmation-details {
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
}

.shipping-info, .payment-info {
  margin-bottom: 20px;
}

.shipping-info h4, .payment-info h4 {
  margin-bottom: 10px;
  color: #409EFF;
}
</style> 