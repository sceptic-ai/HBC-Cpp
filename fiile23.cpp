#include "dataexchange.hpp"
#include "base58.hpp"
#include "utils.hpp"

using namespace std;

//remove an data market, can only be made by the market owner.
//we can only remove a suspended market with enough suspend time to make the inflight deals finished.
//removed market will not be removed from the market table because this table will not be to big.
//we kept the removed market alive because it can show some statistics about data trading.
void dataexchange::removemarket(account_name owner, uint64_t marketid){
    require_auth(owner);

    auto iter = _markets.find(marketid);
    eosio_assert(iter != _markets.end(), "market not have been created yet");
    eosio_assert(iter->mowner == owner , "have no permission to this market");
    eosio_assert(iter->issuspended == true, "only suspended market can be removed");
    eosio_assert(iter->isremoved != true, "this market has already been removed");
    eosio_assert(time_point_sec(now()) > iter->minremovaltime, 
                 "market should have enought suspend time before removal");

    eosio_assert(iter->mstats.inflightdeals_nr == 0, "market can't be removed because there are some inflight deals");

    marketordertable orders(_self, owner);
    auto orderiter = orders.begin();
    auto removedorders = 0;
    while(true) {
        if (orderiter != orders.end()) {
            eosio_assert(orderiter->ostats.o_inflightdeals_nr == 0, "order can't be removed because there are some inflight deals");
            removedorders++;
            orders.erase(orderiter++);
        } else {
            break;
        }
    }

    _markets.modify( iter, 0, [&]( auto& mkt) {
        mkt.isremoved = true;
        mkt.mstats.suspendedorders_nr -= removedorders;
        mkt.mstats.totalopenorders_nr -= removedorders;
    });
}

//create an new data market, only the contract owner can create a market.
//a datasource can have ONLY ONE living data market, but can have lots of removed markets.
void dataexchange::createmarket(account_name owner, uint64_t type, string desp){
    require_auth(_self);

    eosio_assert(desp.length() < 30, "market description should be less than 30 characters");
    eosio_assert(cancreate(owner) == true, "an account can only create only one market now");
    eosio_assert((type > typestart && type < typeend), "out of market type");

    uint64_t newid = 0;
    if (_availableid.exists()) {
        auto iditem = _availableid.get();
        newid = ++iditem.availmarketid;
        _availableid.set(iditem, _self);
    } else {
        _availableid.set(availableid(), _self);
    }

    _markets.emplace( _self, [&]( auto& row) {
        row.marketid = newid;
        row.mowner = owner;
        row.mtype = type;
        row.mdesp = desp;
        row.minremovaltime = time_point_sec(0);
        row.issuspended = false;
    });
}

//suspend an market so no more orders can be made, this abi is for market management concern.
void dataexchange::suspendmkt(account_name owner, uint64_t marketid){
    //only the market owner can suspend a market
    require_auth(owner);

    auto iter = _markets.find(marketid);
    eosio_assert(iter != _markets.end(), "market not have been created yet");
    eosio_assert(iter->mowner == owner , "have no permission to this market");
    eosio_assert(iter->issuspended == false, "market should be work now");

    marketordertable orders(_self, owner);
    auto suspendedorders = 0;
    auto orderiter = orders.begin();
    while(true) {
        if (orderiter != orders.end()) {
            suspendedorders++;
            orders.modify( orderiter, 0, [&]( auto& order) {
                order.issuspended = true;
            });
            orderiter++;
        } else {
            break;
        }
    }
    _markets.modify( iter, 0, [&]( auto& mkt) {
        mkt.issuspended = true;
        mkt.mstats.suspendedorders_nr += suspendedorders;
        mkt.minremovaltime = time_point_sec(now() + market_min_suspendtoremoveal_interval);
    });
}

//resume a suspended data market.
void dataexchange::resumemkt(account_name owner, uint64_t marketid){
    //only the market owner can resume a market
    require_auth(owner);

    auto iter = _markets.find(marketid);
    eosio_assert(iter != _markets.end(), "market not have been created yet");
    eosio_assert(iter->mowner == owner , "have no permission to this market");
    eosio_assert(iter->issuspended == true, "market should be suspened");

    marketordertable orders(_self, owner);
    auto orderiter = orders.begin();
    auto resumedorders = 0;
    while(true) {
        if (orderiter != orders.end()) {
            resumedorders++;
            orders.modify( orderiter, 0, [&]( auto& order) {
                order.issuspended = true;
            });
            orderiter++;
        } else {
            break;
        }
    }
    _markets.modify( iter, 0, [&]( auto& mkt) {
        mkt.issuspended = false;
        mkt.mstats.suspendedorders_nr -= resumedorders;
        mkt.minremovaltime = time_point_sec(0);
    });
}

// create an order in a market, deals can be made under this order.
void dataexchange::createorder(account_name orderowner, uint64_t ordertype, uint64_t marketid, asset& price) {
    require_auth(orderowner);

    eosio_assert( price.is_valid(), "invalid price" );
    eosio_assert( price.amount > 0, "price must be positive price" );
    eosio_assert( ordertype < ordertype_end, "bad ordertype" );

    auto miter = _markets.find(marketid);
    eosio_assert(miter != _markets.end(), "market not have been created yet");
    eosio_assert(miter->isremoved != true, "market has already been removed");
    eosio_assert(miter->mowner != orderowner, "please don't trade on your own market");
    eosio_assert(miter->issuspended != true, "market has already suspened, can't create orders");

    marketordertable orders(_self, miter->mowner); 
    eosio_assert( hasorder_byorderowner(miter->mowner, orderowner) != true, 
                  "one user can only create a single order");

    auto iditem = _availableid.get();
    auto newid = ++iditem.availorderid;
    _availableid.set(availableid(iditem.availmarketid, newid, iditem.availdealid), _self);

    // we can only put it to the contract owner scope
    orders.emplace(orderowner, [&]( auto& order) {
        order.orderid = newid;
        order.orderowner = orderowner;
        order.order_type = ordertype;
        order.marketid = marketid;
        order.price = price;
    });

    //reg seller to accounts table 
    auto itr = _accounts.find(orderowner);
    if( itr == _accounts.end() ) {
        itr = _accounts.emplace(_self, [&](auto& acnt){
           acnt.owner = orderowner;
        });
    }

    _markets.modify( miter, 0, [&]( auto& mkt) {
        mkt.mstats.totalopenorders_nr++;
    });
}

//suspend an order so buyers can not make deals in this order.
void dataexchange::suspendorder(account_name orderowner, account_name marketowner, uint64_t orderid) {
    require_auth(orderowner);

    marketordertable orders(_self, marketowner);
    auto iter = orders.find(orderid);

    eosio_assert(iter != orders.end() , "no such order");
    eosio_assert(iter->orderowner == orderowner, "order doesn't belong to you");
    eosio_assert(iter->issuspended == false, "order should be work");
    orders.modify( iter, 0, [&]( auto& order) {
        order.issuspended = true;
    });

    auto miter = _markets.find(iter->marketid);
    _markets.modify( miter, 0, [&]( auto& mkt) {
        mkt.mstats.suspendedorders_nr++;
    });
}

//resume an suspended order.
void dataexchange::resumeorder(account_name orderowner, account_name marketowner, uint64_t orderid) {
    require_auth(orderowner);

    marketordertable orders(_self, marketowner);
    auto iter = orders.find(orderid);

    eosio_assert(iter != orders.end() , "no such order");
    eosio_assert(iter->orderowner == orderowner, "order doesn't belong to you");
    eosio_assert(iter->issuspended == true, "order should be suspened");
    orders.modify( iter, 0, [&]( auto& order) {
        order.issuspended = false;
    });
    auto miter = _markets.find(iter->marketid);
    _markets.modify( miter, 0, [&]( auto& mkt) {
        mkt.mstats.suspendedorders_nr--;
    });
}

//remove from data source so no new deals can be made, but inflight deals still can be finished.
void dataexchange::removeorder(account_name orderowner, account_name marketowner, uint64_t orderid) {
    require_auth(orderowner);

    marketordertable orders(_self, marketowner);
    auto iter = orders.find(orderid);

    eosio_assert(iter != orders.end() , "no such order");
    eosio_assert(iter->orderowner == orderowner, "order doesn't belong to you");

    //if there is inflight deals, please erase it before removing a order
    eosio_assert(iter->ostats.o_inflightdeals_nr == 0, "please erase or cancel deal before removing an order");

    auto miter = _markets.find(iter->marketid);
    _markets.modify( miter, 0, [&]( auto& mkt) {
        mkt.mstats.totalopenorders_nr--;
        if (iter->issuspended) {
            mkt.mstats.suspendedorders_nr--;
        }
    });

    orders.erase(iter);
}

//cancel an inflight deal both sides
void dataexchange::canceldeal(account_name canceler, account_name owner, uint64_t dealid) {
    require_auth(canceler);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    eosio_assert(dealiter->dealstate == dealstate_waitinghash || dealiter->dealstate == dealstate_waitingauthorize || 
                 dealiter->dealstate == dealstate_expired, 
                 "deal state is not dealstate_waitinghash");
    eosio_assert(dealiter->maker == canceler || dealiter->taker == canceler, "only maker or taker can cancel a deal");

    auto mktiter = _markets.find(dealiter->marketid);
    eosio_assert(mktiter != _markets.end(), "no such market");

    _deals.erase(dealiter);
    account_name buyer, seller;
    if (dealiter->ordertype == ordertype_ask) {
        buyer = dealiter->taker;
        seller = dealiter->maker;
    } else if (dealiter->ordertype == ordertype_bid) {
        buyer = dealiter->maker;
        seller = dealiter->taker;
    }

    // refund buyer's tokens
    auto buyeritr = _accounts.find(buyer);
    eosio_assert(buyeritr != _accounts.end() , "buyer should have have account");
    _accounts.modify( buyeritr, 0, [&]( auto& acnt ) {
        acnt.asset_balance += dealiter->price;
        acnt.inflightbuy_deals--;
    });

    auto selleritr = _accounts.find(seller);
    eosio_assert(selleritr != _accounts.end() , "seller should have have account");
    _accounts.modify( selleritr , 0, [&]( auto& acnt ) {
        acnt.inflightsell_deals--;
    });


    _markets.modify( mktiter, 0, [&]( auto& mkt) {
        mkt.mstats.inflightdeals_nr--;
    });

    marketordertable orders(_self, dealiter->marketowner);
    auto iter = orders.find(dealiter->orderid);
    eosio_assert(iter != orders.end() , "no such order");

    orders.modify( iter, 0, [&]( auto& order) {
        order.ostats.o_inflightdeals_nr--;
    });
}

//erase deal from ledger to free the memory usage.
void dataexchange::erasedeal(uint64_t dealid) {
    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    auto state = dealiter->dealstate;
    if (dealiter->dealstate != dealstate_finished && dealiter->dealstate != dealstate_wrongsecret && dealiter->expiretime < time_point_sec(now())) {
        state = dealstate_expired;
    }

    eosio_assert(dealiter->dealstate == dealstate_finished || state == dealstate_expired || dealiter->dealstate == dealstate_wrongsecret, 
                 "deal state is not dealstate_finished、dealstate_expired or dealstate_wrongsecret");

    account_name buyer, seller;
    if (dealiter->ordertype == ordertype_ask) {
        buyer = dealiter->taker;
        seller = dealiter->maker;
    } else if (dealiter->ordertype == ordertype_bid) {
        buyer = dealiter->maker;
        seller = dealiter->taker;
    }

    if (state == dealstate_expired) {
        auto buyeritr = _accounts.find(buyer);
        _accounts.modify( buyeritr, 0, [&]( auto& acnt ) {
            acnt.expired_deals++;
            acnt.inflightbuy_deals--;
        });
        auto selleritr = _accounts.find(seller);
        _accounts.modify( selleritr, 0, [&]( auto& acnt ) {
            acnt.expired_deals++;
            acnt.inflightsell_deals--;
        });
    }

    if (dealiter->dealstate != dealstate_finished) {
        auto mktiter = _markets.find(dealiter->marketid);
        eosio_assert(mktiter != _markets.end(), "no such market");
        _markets.modify( mktiter, 0, [&]( auto& mkt) {
            mkt.mstats.inflightdeals_nr--;
        });
    }

    if (dealiter->dealstate != dealstate_finished) {
        marketordertable orders(_self, dealiter->marketowner);
        auto iter = orders.find(dealiter->orderid);
        eosio_assert(iter != orders.end() , "no such order");

        orders.modify( iter, 0, [&]( auto& order) {
            order.ostats.o_inflightdeals_nr--;
        });
    }

    _deals.erase(dealiter);
}

//owner is the market owner, market owner must be provided because all orders are stored in market owner's scope.
//see code: marketordertable orders(_self, marketowner);
//taker is the one who try to make a deal by taking an existing order.
void dataexchange::makedeal(account_name taker, account_name marketowner, uint64_t orderid) {
    require_auth(taker);

    marketordertable orders(_self, marketowner);
    auto iter = orders.find(orderid);

    eosio_assert(iter != orders.end() , "no such order");
    eosio_assert(iter->issuspended != true , "can not make deals because the order is suspended");
    auto mktiter = _markets.find(iter->marketid);
    eosio_assert(mktiter != _markets.end(), "no such market");

    uint64_t otype = iter->order_type;
    eosio_assert( otype < ordertype_end, "bad ordertype" );

    account_name buyer, seller;
    if (otype == ordertype_ask) {
        buyer = taker;
        seller = iter->orderowner;
    } else if (otype == ordertype_bid) {
        buyer = iter->orderowner;
        seller = taker;
    }

    //if order type is ask, then the taker is a buyer
    auto buyeriter = _accounts.find(buyer);
    if( buyeriter == _accounts.end() ) {
        _accounts.emplace(_self, [&](auto& acnt){
            acnt.owner = buyer;
        });
    }

    _accounts.modify( buyeriter, 0, [&]( auto& acnt ) {
        eosio_assert(acnt.asset_balance >= iter->price , "buyer should have enough token");

        //deduct token from the buyer's account
        acnt.asset_balance -= iter->price;
        acnt.inflightbuy_deals++;
    });

    auto selleritr = _accounts.find(seller);
    //reg seller to accounts table 
    if( selleritr == _accounts.end() ) {
        _accounts.emplace(_self, [&](auto& acnt){
            acnt.owner = seller;
            acnt.inflightsell_deals++; 
        });
    } else {
        _accounts.modify( selleritr, 0, [&]( auto& acnt ) {
            acnt.inflightsell_deals++;
        });
    }

    auto iditem = _availableid.get();
    auto newid = ++iditem.availdealid;
    _availableid.set(availableid(iditem.availmarketid, iditem.availorderid, newid), _self);

    //use self scope to make it simple for memory reclaiming.
    _deals.emplace(_self, [&](auto& deal) { 
        deal.dealid = newid;
        deal.marketowner = marketowner;
        deal.orderid = orderid;
        deal.marketid = iter->marketid;
        deal.source_datahash = "";
        deal.seller_datahash = "";
        deal.dealstate = dealstate_waitingauthorize;
        deal.ordertype = otype;
        deal.maker = iter->orderowner;
        deal.taker = taker;
        deal.price = iter->price;
        deal.expiretime = time_point_sec(now() + deal_expire_interval);
    });

    _markets.modify( mktiter, 0, [&]( auto& mkt) {
        mkt.mstats.inflightdeals_nr++;
    });
    orders.modify( iter, 0, [&]( auto& order) {
        order.ostats.o_inflightdeals_nr++;
    });
}

//maker authorize a deal, all deals are stored in contract owner's scope.
void dataexchange::authorize(account_name maker, uint64_t dealid) {
    require_auth(maker);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    eosio_assert(dealiter->dealstate == dealstate_waitingauthorize, "deal state is not dealstate_waitingauthorize");
    eosio_assert(dealiter->maker == maker, "this deal doesnot belong to you");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "this deal has been expired");
    _deals.modify( dealiter, 0, [&]( auto& deal) {
        deal.dealstate = dealstate_waitingpubA;
    });
}

//datahash is generated using the buyers public key encrypted user's data.
//uploadhash is called by datasource(aka market owner).
void dataexchange::uploadhash(account_name sender, uint64_t dealid, string datahash) {
    require_auth(sender);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    eosio_assert(dealiter->dealstate == dealstate_waitinghash, "deal state is not dealstate_waitinghash");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "this deal has been expired");

    auto mktiter = _markets.find(dealiter->marketid);
    eosio_assert(mktiter != _markets.end(), "no such market");


    _deals.modify( dealiter, 0, [&]( auto& deal) {
        if (sender == dealiter->marketowner) {
            eosio_assert(dealiter->source_datahash == "", "don't send hash more than once");
            deal.source_datahash = datahash;
        } else {
            account_name _seller;
            if (dealiter->ordertype == ordertype_ask) {
                _seller = dealiter->maker;
            } else if (dealiter->ordertype == ordertype_bid) {
                _seller = dealiter->taker;
            }
            
            eosio_assert(_seller == sender, "only seller can do this");
            eosio_assert(dealiter->seller_datahash == "", "don't send hash more than once");
            deal.seller_datahash = datahash;
        }

        if (deal.seller_datahash != "" && deal.source_datahash != "")
            deal.dealstate = dealstate_waitinghashcomfirm;
    });
}

//a buyer comfirm the ipfs hash is valid
void dataexchange::confirmhash(account_name buyer, uint64_t dealid) {
    require_auth(buyer);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    auto state = dealiter->dealstate;
    eosio_assert(state == dealstate_waitinghashcomfirm, "deal state is not waiting dealstate_waitinghashcomfirm");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "deal is already expired");

    account_name _buyer;
    if (dealiter->ordertype == ordertype_ask) {
        _buyer = dealiter->taker;
    } else if (dealiter->ordertype == ordertype_bid) {
        _buyer = dealiter->maker;
    }

    eosio_assert(_buyer == buyer, "buyer is not correct");
    _deals.modify( dealiter, 0, [&]( auto& deal) {
        deal.dealstate = dealstate_waitingpria;
    });
}

//deposit token to contract, all token will transfer to contract owner.
void dataexchange::deposit(account_name from, asset& quantity ) {
    require_auth( from);
   
    eosio_assert( quantity.is_valid(), "invalid quantity" );
    eosio_assert( quantity.amount > 0, "must deposit positive quantity" );

    auto itr = _accounts.find(from);
    if( itr == _accounts.end() ) {
        itr = _accounts.emplace(_self, [&](auto& acnt){
            acnt.owner = from;
        });
    }

    _accounts.modify( itr, 0, [&]( auto& acnt ) {
        acnt.asset_balance += quantity;
    });

    //make sure contract xingyitoken have been deployed to blockchain to make it runnable
    //xingyitoken is our own token, its symbol is SYS
    action(
        permission_level{ from, N(active) },
        N(xingyitoken), N(transfer),
        std::make_tuple(from, _self, quantity, std::string("deposit token"))
    ).send();
}

//withdraw token from contract owner, token equals to quantity will transfer to owner.
void dataexchange::withdraw(account_name owner, asset& quantity ) {
    require_auth( owner );

    eosio_assert( quantity.is_valid(), "invalid quantity" );
    eosio_assert( quantity.amount > 0, "must withdraw positive quantity" );

    auto itr = _accounts.find( owner );
    eosio_assert(itr != _accounts.end(), "account has no fund, can't withdraw");

    _accounts.modify( itr, 0, [&]( auto& acnt ) {
        eosio_assert( acnt.asset_balance >= quantity, "insufficient balance" );
        acnt.asset_balance -= quantity;
    });

    //make sure contract xingyitoken have been deployed to blockchain to make it runnable
    //xingyitoken is our own token, its symblo is SYS
    action(
        permission_level{ _self, N(active) },
        N(xingyitoken), N(transfer),
        std::make_tuple(_self, owner, quantity, std::string("withdraw token"))
    ).send();

    // erase account when no more fund to free memory 
    if( itr->asset_balance.amount == 0 && itr->pkey.length() == 0 && 
        itr->finished_deals == 0 && itr->inflightbuy_deals == 0 && itr->inflightsell_deals == 0) {
       _accounts.erase(itr);
    }
}

//register public key to ledger, the data source can encrypt data by this public key.
void dataexchange::regpkey(account_name owner, string pkey) {
    require_auth( owner );

    pkey.erase(pkey.begin(), find_if(pkey.begin(), pkey.end(), [](int ch) {
        return !isspace(ch);
    }));
    pkey.erase(find_if(pkey.rbegin(), pkey.rend(), [](int ch) {
        return !isspace(ch);
    }).base(), pkey.end());

    eosio_assert(pkey.length() == 53, "Length of public key should be 53");
    string pubkey_prefix("EOS");
    auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), pkey.begin());
    eosio_assert(result.first == pubkey_prefix.end(), "Public key should be prefix with EOS");

    auto base58substr = pkey.substr(pubkey_prefix.length());
    vector<unsigned char> vch;
    //(fixme)decode_base58 can be very time-consuming, must remove it in the future.
    eosio_assert(decode_base58(base58substr, vch), "Decode public failed");
    eosio_assert(vch.size() == 37, "Invalid public key: invalid base58 length");

    array<unsigned char,33> pubkey_data;
    copy_n(vch.begin(), 33, pubkey_data.begin());

    checksum160 check_pubkey;
    ripemd160(reinterpret_cast<char *>(pubkey_data.data()), 33, &check_pubkey);
    eosio_assert(memcmp(&check_pubkey.hash, &vch.end()[-4], 4) == 0, "Invalid public key: invalid checksum");

    auto itr = _accounts.find( owner );
    if( itr == _accounts.end() ) {
        itr = _accounts.emplace(_self, [&](auto& acnt){
            acnt.owner = owner;
        });
    }

    _accounts.modify( itr, 0, [&]( auto& acnt ) {
        acnt.pkey = pkey;
    });
}

//deregister public key, aka remove from ledger.
void dataexchange::deregpkey(account_name owner) {
    require_auth( owner );

    auto itr = _accounts.find( owner );
    eosio_assert(itr != _accounts.end(), "account not registered yet");

    //reducer uncessary account erasal
    if (itr->asset_balance.amount > 0 || itr->finished_deals > 0 || itr->inflightbuy_deals > 0 || itr->inflightsell_deals > 0) {
        _accounts.modify( itr, 0, [&]( auto& acnt ) {
            acnt.pkey = "";
        });
    } else {
        _accounts.erase(itr);
    }
}

//a seller upload public A param
void dataexchange::uploadpuba(account_name seller, uint64_t dealid, uint64_t puba) {
    require_auth(seller);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    auto state = dealiter->dealstate;
    eosio_assert(state == dealstate_waitingpubA, "deal state is not waiting dealstate_waitingpubA");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "deal is already expired");

    account_name _seller;
    if (dealiter->ordertype == ordertype_ask) {
        _seller = dealiter->maker;
    } else if (dealiter->ordertype == ordertype_bid) {
        _seller = dealiter->taker;
    }

    eosio_assert(_seller == seller, "seller is not correct");
    _deals.modify( dealiter, 0, [&]( auto& deal) {
        deal.dealstate = dealstate_waitingpubB;
        deal.dhp.pubA = puba;
    });
}

//a datasource upload public B param
void dataexchange::uploadpubb(account_name datasource, uint64_t dealid, uint64_t pubb) {
    require_auth(datasource);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    auto state = dealiter->dealstate;
    eosio_assert(state == dealstate_waitingpubB, "deal state is not waiting dealstate_waitingpubB");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "deal is already expired");
    eosio_assert(dealiter->marketowner == datasource, "datasource is not correct");

    _deals.modify( dealiter, 0, [&]( auto& deal) {
        deal.dealstate = dealstate_waitinghash;
        deal.dhp.pubB = pubb;
    });
}

//a seller upload the private secret a
void dataexchange::uploadpria(account_name seller, uint64_t dealid, uint64_t pria){
    require_auth(seller);

    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    auto state = dealiter->dealstate;
    eosio_assert(state == dealstate_waitingpria, "deal state is not waiting dealstate_waitingpria");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "deal is already expired");

    account_name _seller;
    if (dealiter->ordertype == ordertype_ask) {
        _seller = dealiter->maker;
    } else if (dealiter->ordertype == ordertype_bid) {
        _seller = dealiter->taker;
    }

    eosio_assert(_seller == seller, "seller is not correct");
    _deals.modify( dealiter, 0, [&]( auto& deal) {
        deal.dealstate = dealstate_waitingprib;
        deal.dhp.pria = pria;
    });
}

//a datasource upload the private secret b
void dataexchange::uploadprib(uint64_t marketid, uint64_t dealid, uint64_t prib) {
    auto dealiter = _deals.find(dealid);
    eosio_assert(dealiter != _deals.end() , "no such deal");
    eosio_assert(dealiter->dealstate == dealstate_waitingprib, "deal state is not dealstate_waitingprib");
    eosio_assert(dealiter->marketid == marketid, "not correct marketid");
    eosio_assert(dealiter->expiretime > time_point_sec(now()), "this deal has been expired");

    auto mktiter = _markets.find(dealiter->marketid);
    eosio_assert(mktiter != _markets.end(), "no such market");

    //this abi should only run by the market owner
    require_auth(mktiter->mowner);
    dhparams dhp = dealiter->dhp;
    eosio_assert(mktiter != _markets.end(), "no such market");

    auto otype = dealiter->ordertype;
    account_name buyer, seller;
    if (otype == ordertype_ask) {
        buyer = dealiter->taker;
        seller = dealiter->maker;
    } else if (otype == ordertype_bid) {
        buyer = dealiter->maker;
        seller = dealiter->taker;
    }
    auto selleriter = _accounts.find(seller);
    if( selleriter == _accounts.end() ) {
        selleriter = _accounts.emplace(_self, [&](auto& acnt){
            acnt.owner = seller;
        });
    }

    // modify buyers finished order data
    auto buyeriter = _accounts.find(buyer);
    eosio_assert(buyeriter != _accounts.end(), "buyer should have account");

    // add token to data source account
    auto sourceitr = _accounts.find(dealiter->marketowner);
    if( sourceitr == _accounts.end() ) {
        sourceitr = _accounts.emplace(_self, [&](auto& acnt){
            acnt.owner = dealiter->marketowner;
        });
    }
    marketordertable orders(_self, dealiter->marketowner);
    auto iter = orders.find(dealiter->orderid);
    eosio_assert(iter!= orders.end() , "no such order");

    //secret check failed, this is a wrong secret
    //(fixme)powmodp cost to much cpu resource, the the test case, it cost 14996us, 10 times higher than ordinary operations.
    //maybe ecdh is cost less cpu time, we should try it asap.
    if (powmodp(dhp.pubA, prib) != powmodp(dhp.pubB, dhp.pria)) {
        _deals.modify( dealiter, 0, [&]( auto& deal) {
            deal.dhp.prib = prib;
            deal.dealstate = dealstate_wrongsecret;
        });
        
        _accounts.modify( buyeriter, 0, [&]( auto& acnt ) {
            //refund to buyer because the seller and datasource are suspect to telling lies about the data.
            acnt.asset_balance += dealiter->price;
        });
        //we only set the seller as suspicious
        _accounts.modify( selleriter, 0, [&]( auto& acnt ) {
            acnt.suspicious_deals++;
        });

        _markets.modify( mktiter, 0, [&]( auto& mkt) {
            mkt.mstats.suspiciousdeals_nr++;
        });
        orders.modify( iter, 0, [&]( auto& order) {
            order.ostats.o_suspiciousdeals_nr++;
        });    
    } else {
        _deals.modify( dealiter, 0, [&]( auto& deal) {
            deal.dealstate = dealstate_finished;
            deal.dhp.prib = prib;
            deal.secret = powmodp(dhp.pubA, prib);
        });

        auto sellertoken = asset(uint64_t(0.9 * dealiter->price.amount));
        auto sourcetoken = asset(uint64_t(0.1 * dealiter->price.amount));

        // add token to seller's account

        _accounts.modify( selleriter, 0, [&]( auto& acnt ) {
            acnt.asset_balance += sellertoken;
            acnt.finished_deals++;
            acnt.inflightsell_deals--;
        });

        _accounts.modify( sourceitr, 0, [&]( auto& acnt ) {
            acnt.asset_balance += sourcetoken;
        });    

        _accounts.modify( buyeriter, 0, [&]( auto& acnt ) {
            acnt.inflightbuy_deals--;
            acnt.finished_deals++;
        });

        _markets.modify( mktiter, 0, [&]( auto& mkt) {
            mkt.mstats.inflightdeals_nr--;
            mkt.mstats.finisheddeals_nr++;
            mkt.mstats.tradingincome_nr += sourcetoken;
            mkt.mstats.tradingvolume_nr += dealiter->price;
        });

        orders.modify( iter, 0, [&]( auto& order) {
            order.ostats.o_inflightdeals_nr--;
            order.ostats.o_finisheddeals_nr++;
            order.ostats.o_finishedvolume_nr += dealiter->price;
        });    
    }
}

//this abi will generate an dealid
void dataexchange::directdeal(account_name buyer, account_name seller, asset &price, string data_spec){

}

void dataexchange::higherprice(account_name seller, uint64_t dealid, asset &price) {
    require_auth(seller);
    return;
}
void dataexchange::directredeal(account_name buyer, uint64_t dealid, asset &price, string data_spec) {

}

void dataexchange::directhash(account_name buyer, account_name seller, asset &price){

}

void dataexchange::directack(account_name buyer, uint64_t dealid){

}

void dataexchange::directsecret(uint64_t marketid, uint64_t dealid, string secret){

}
