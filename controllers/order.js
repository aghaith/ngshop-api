import asyncHandler from 'express-async-handler';
import Order from '../models/order.js';
import OrderItem from '../models/order-item.js';

const list = asyncHandler(async (req, res) => {
    Order
        .find().populate('user', 'name').sort({ 'dateOrdered': -1 }) //newest to oldest
        .exec((err, orders) => {
            if (err) {
                 res.status(400).json({
                    error: 'Orders not found'
                })
            }
            res.json(orders);
        });
});

const create = asyncHandler(async (req, res) => {
    const orderItemsIds = Promise.all(req.body.orderItems.map(async (orderItem) => {
        let newOrderItem = new OrderItem({
            quantity: orderItem.quantity,
            product: orderItem.product
        })

        newOrderItem = await newOrderItem.save();
        return newOrderItem._id;
    }));

    const orderItemsIdsResolved = await orderItemsIds;

    const totalPrices = await Promise.all(orderItemsIdsResolved.map(async (orderItemId)=>{
        const orderItem = await OrderItem.findById(orderItemId).populate('product', 'price');
        const totalPrice = orderItem.product.price * orderItem.quantity;
        return totalPrice;
    }));

    const totalPrice = totalPrices.reduce((a,b) => a + b , 0);

    const order = new Order({
        orderItems: orderItemsIdsResolved,
        shippingAddress1: req.body.shippingAddress1,
        shippingAddress2: req.body.shippingAddress2,
        city: req.body.city,
        zip: req.body.zip,
        country: req.body.country,
        phone: req.body.phone,
        totalPrice: totalPrice,
        user: req.body.user,
    });

    const createdOrder = await order.save()

    if (!order)
        res.status(500).json({
            message: 'Order cannot be created'
        });

    res.status(201).json(createdOrder);
});

const orderById = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id)
        .populate('user', 'name')
        .populate({
            path: 'orderItems', populate: {
                path: 'product', populate: 'category'
            }
        });

    if (order) {
        res.json(order)
    } else {
        res.status(404).json({
            message: 'Order not Found',
            success: false
        })
    }
});

const updateOrderStatus = asyncHandler(async (req, res) => {

    const {
        status
    } = req.body

    const order = await Order.findById(req.params.id)

    if (order) {
        order.status = status

        const updatedOrderStatus = await order.save()
        res.json(updatedOrderStatus)
    } else {
        res.status(404).json({
            message: 'Order not Found',
            success: false
        })
    }
});

const remove = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id)

    if (order) {
        await order.remove()
        await order.orderItems.map(async orderItem => {
            await OrderItem.findByIdAndRemove(orderItem)
        })
         res.status(200).json({
            success: true,
            message: 'Order removed'
        })
    } else {
         res.status(404).json({
            success: false,
            message: 'Order not Found'
        })
    }
});

const totalSales = asyncHandler(async (req, res) => {
    const totalSales= await Order.aggregate([
        { $group: { _id: null , totalsales : { $sum : '$totalPrice'}}}
    ])

    if(!totalSales) {
         res.status(400).json({
            message: 'Order sales cannot be generated'
        })
    } else {
        res.json({
            totalsales: totalSales.pop().totalsales
        })
    }
});

const countOrders = asyncHandler(async (req, res) => {
    const orderCount = await Order.countDocuments()
    if(!orderCount) {
        res.status(500).json({success: false})
    } 
    res.send({
        orderCount: orderCount
    });
});

const userOrders = asyncHandler(async (req, res) => {
    const userOrderList = await Order.find({
        user: req.params.userid
    })
    .populate({ 
        path: 'orderItems', 
        populate: {
            path : 'product', 
            populate: 'category'
        } 
    })
    .sort({
        'dateOrdered': -1
    });
    if(!userOrderList) {
        res.status(500).json({success: false})
    } 
    res.send(userOrderList);
});

export {
    list,
    create,
    orderById,
    updateOrderStatus,
    remove,
    totalSales,
    countOrders,
    userOrders
}