<template>
  <div class="profile">
    <h1>My Profile</h1>
    
    <el-tabs>
      <!-- Personal Information -->
      <el-tab-pane label="Personal Info">
        <el-form :model="userInfo" label-width="120px">
          <el-form-item label="Username">
            <el-input v-model="userInfo.username" disabled></el-input>
          </el-form-item>
          <el-form-item label="Email">
            <el-input v-model="userInfo.email"></el-input>
          </el-form-item>
          <el-form-item label="New Password">
            <el-input v-model="userInfo.newPassword" type="password" show-password></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="updateProfile">Save Changes</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- Addresses -->
      <el-tab-pane label="Addresses">
        <div class="address-list">
          <el-button type="primary" @click="showAddressDialog('add')" class="add-button">
            Add New Address
          </el-button>
          
          <el-empty v-if="addresses.length === 0" description="No addresses yet"></el-empty>
          
          <el-card v-for="address in addresses" :key="address.id" class="address-card">
            <div class="address-content">
              <div class="address-info">
                <p><strong>Street:</strong> {{ address.street }}</p>
                <p><strong>City:</strong> {{ address.city }}</p>
                <p><strong>State:</strong> {{ address.state }}</p>
                <p><strong>Country:</strong> {{ address.country }}</p>
                <p><strong>Zip Code:</strong> {{ address.zipCode }}</p>
                <el-tag v-if="address.isDefault" type="success">Default</el-tag>
              </div>
              <div class="address-actions">
                <el-button @click="showAddressDialog('edit', address)" type="primary" plain>Edit</el-button>
                <el-button 
                  @click="deleteAddress(address.id)" 
                  type="danger" 
                  plain
                  :disabled="address.isDefault">
                  Delete
                </el-button>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>

      <!-- Payment Methods -->
      <el-tab-pane label="Payment Methods">
        <div class="payment-methods">
          <el-button type="primary" @click="showCardDialog('add')" class="add-button">
            Add New Card
          </el-button>
          
          <el-empty v-if="creditCards.length === 0" description="No payment methods yet"></el-empty>
          
          <el-card v-for="card in creditCards" :key="card.id" class="card-item">
            <div class="card-content">
              <div class="card-info">
                <p><strong>Card Number:</strong> **** **** **** {{ card.cardNumber.slice(-4) }}</p>
                <p><strong>Card Holder:</strong> {{ card.cardHolderName }}</p>
                <p><strong>Expires:</strong> {{ card.expirationMonth }}/{{ card.expirationYear }}</p>
                <el-tag v-if="card.isDefault" type="success">Default</el-tag>
              </div>
              <div class="card-actions">
                <el-button @click="showCardDialog('edit', card)" type="primary" plain>Edit</el-button>
                <el-button 
                  @click="deleteCard(card.id)" 
                  type="danger" 
                  plain
                  :disabled="card.isDefault">
                  Delete
                </el-button>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- Address Dialog -->
    <el-dialog 
      :title="addressDialog.type === 'add' ? 'Add New Address' : 'Edit Address'"
      v-model="addressDialog.visible"
      width="500px">
      <el-form :model="addressDialog.form" label-width="120px">
        <el-form-item label="Street">
          <el-input v-model="addressDialog.form.street"></el-input>
        </el-form-item>
        <el-form-item label="City">
          <el-input v-model="addressDialog.form.city"></el-input>
        </el-form-item>
        <el-form-item label="State">
          <el-input v-model="addressDialog.form.state"></el-input>
        </el-form-item>
        <el-form-item label="Country">
          <el-input v-model="addressDialog.form.country"></el-input>
        </el-form-item>
        <el-form-item label="Zip Code">
          <el-input v-model="addressDialog.form.zipCode"></el-input>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="addressDialog.form.isDefault">Set as default address</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addressDialog.visible = false">Cancel</el-button>
        <el-button type="primary" @click="saveAddress">Save</el-button>
      </template>
    </el-dialog>

    <!-- Credit Card Dialog -->
    <el-dialog 
      :title="cardDialog.type === 'add' ? 'Add New Card' : 'Edit Card'"
      v-model="cardDialog.visible"
      width="500px">
      <el-form :model="cardDialog.form" label-width="120px">
        <el-form-item label="Card Number">
          <el-input v-model="cardDialog.form.cardNumber"></el-input>
        </el-form-item>
        <el-form-item label="Card Holder">
          <el-input v-model="cardDialog.form.cardHolderName"></el-input>
        </el-form-item>
        <el-form-item label="Expiration">
          <el-row :gutter="10">
            <el-col :span="12">
              <el-select v-model="cardDialog.form.expirationMonth" placeholder="Month">
                <el-option 
                  v-for="month in 12" 
                  :key="month"
                  :label="String(month).padStart(2, '0')"
                  :value="month">
                </el-option>
              </el-select>
            </el-col>
            <el-col :span="12">
              <el-select v-model="cardDialog.form.expirationYear" placeholder="Year">
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
          <el-input v-model="cardDialog.form.cvv" maxlength="4"></el-input>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="cardDialog.form.isDefault">Set as default card</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="cardDialog.visible = false">Cancel</el-button>
        <el-button type="primary" @click="saveCard">Save</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

const userInfo = ref({
  username: '',
  email: '',
  newPassword: ''
})

const addresses = ref([])
const creditCards = ref([])
const currentYear = new Date().getFullYear()

// Address Dialog
const addressDialog = ref({
  visible: false,
  type: 'add',
  form: {
    street: '',
    city: '',
    state: '',
    country: '',
    zipCode: '',
    isDefault: false
  }
})

// Credit Card Dialog
const cardDialog = ref({
  visible: false,
  type: 'add',
  form: {
    cardNumber: '',
    cardHolderName: '',
    expirationMonth: null,
    expirationYear: null,
    cvv: '',
    isDefault: false
  }
})

// Load user data
const loadUserData = async () => {
  try {
    const response = await axios.get('/api/profile')
    userInfo.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load user data')
  }
}

// Load addresses
const loadAddresses = async () => {
  try {
    const response = await axios.get('/api/profile/addresses')
    addresses.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load addresses')
  }
}

// Load credit cards
const loadCreditCards = async () => {
  try {
    const response = await axios.get('/api/profile/credit-cards')
    creditCards.value = response.data
  } catch (error) {
    ElMessage.error('Failed to load payment methods')
  }
}

// Update profile
const updateProfile = async () => {
  try {
    await axios.put('/api/profile', userInfo.value)
    ElMessage.success('Profile updated successfully')
    userInfo.value.newPassword = ''
  } catch (error) {
    ElMessage.error('Failed to update profile')
  }
}

// Address management
const showAddressDialog = (type, address = null) => {
  addressDialog.value.type = type
  addressDialog.value.visible = true
  if (type === 'edit' && address) {
    addressDialog.value.form = { ...address }
  } else {
    addressDialog.value.form = {
      street: '',
      city: '',
      state: '',
      country: '',
      zipCode: '',
      isDefault: false
    }
  }
}

const saveAddress = async () => {
  try {
    if (addressDialog.value.type === 'add') {
      await axios.post('/api/profile/addresses', addressDialog.value.form)
    } else {
      await axios.put(`/api/profile/addresses/${addressDialog.value.form.id}`, addressDialog.value.form)
    }
    addressDialog.value.visible = false
    loadAddresses()
    ElMessage.success('Address saved successfully')
  } catch (error) {
    ElMessage.error('Failed to save address')
  }
}

const deleteAddress = async (addressId) => {
  try {
    await ElMessageBox.confirm('Are you sure you want to delete this address?')
    await axios.delete(`/api/profile/addresses/${addressId}`)
    loadAddresses()
    ElMessage.success('Address deleted successfully')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete address')
    }
  }
}

// Credit card management
const showCardDialog = (type, card = null) => {
  cardDialog.value.type = type
  cardDialog.value.visible = true
  if (type === 'edit' && card) {
    cardDialog.value.form = { ...card }
  } else {
    cardDialog.value.form = {
      cardNumber: '',
      cardHolderName: '',
      expirationMonth: null,
      expirationYear: null,
      cvv: '',
      isDefault: false
    }
  }
}

const saveCard = async () => {
  try {
    if (cardDialog.value.type === 'add') {
      await axios.post('/api/profile/credit-cards', cardDialog.value.form)
    } else {
      await axios.put(`/api/profile/credit-cards/${cardDialog.value.form.id}`, cardDialog.value.form)
    }
    cardDialog.value.visible = false
    loadCreditCards()
    ElMessage.success('Card saved successfully')
  } catch (error) {
    ElMessage.error('Failed to save card')
  }
}

const deleteCard = async (cardId) => {
  try {
    await ElMessageBox.confirm('Are you sure you want to delete this card?')
    await axios.delete(`/api/profile/credit-cards/${cardId}`)
    loadCreditCards()
    ElMessage.success('Card deleted successfully')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete card')
    }
  }
}

onMounted(() => {
  loadUserData()
  loadAddresses()
  loadCreditCards()
})
</script>

<style scoped>
.profile {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.add-button {
  margin-bottom: 20px;
}

.address-card, .card-item {
  margin-bottom: 20px;
}

.address-content, .card-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.address-info, .card-info {
  flex-grow: 1;
}

.address-info p, .card-info p {
  margin: 5px 0;
}

.address-actions, .card-actions {
  display: flex;
  gap: 10px;
}

.el-tag {
  margin-top: 10px;
}
</style> 