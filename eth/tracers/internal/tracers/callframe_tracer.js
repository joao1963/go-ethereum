// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.


// callFrameTracer uses the new call frame tracing methods to report useful information
// about internal messages of a transaction.
{
    callstack: [{}],
    step: function(log, db) {},
    fault: function(log, db) {
        var len = this.callstack.length
        if (len > 1) {
            var call = this.callstack.pop()
            if (this.callstack[len-1].calls === undefined) {
                this.callstack[len-1].calls = []
            }
            this.callstack[len-1].calls.push(call)
        }
    },
    result: function(ctx, db) {
        // Prepare outer message info
        var call = {
            type:    ctx.type,
            from:    toHex(ctx.from),
            to:      toHex(ctx.to),
            value:   '0x' + ctx.value.toString(16),
            gas:     '0x' + bigInt(ctx.gas).toString(16),
            gasUsed: '0x' + bigInt(ctx.gasUsed).toString(16),
            input:   toHex(ctx.input),
            output:  toHex(ctx.output),
        }
        if (this.callstack[0].calls !== undefined) {
          call.calls = this.callstack[0].calls;
        }
        return call 
    },
    enter: function(frame) {
        var call = {
            type: frame.type,
            from: toHex(frame.from),
            to: toHex(frame.to),
            input: toHex(frame.input),
            gas: '0x' + bigInt(frame.gas).toString('16'),
            value: '0x' + frame.value.toString('16'),
        }
        this.callstack.push(call)
    },
    exit: function(frameResult) {
        var len = this.callstack.length
        if (len > 1) {
            var call = this.callstack.pop()
            call.gasused = '0x' + bigInt(frameResult.gasUsed).toString('16')
            call.output = toHex(frameResult.output)
            len -= 1
            if (this.callstack[len-1].calls === undefined) {
                this.callstack[len-1].calls = []
            }
            this.callstack[len-1].calls.push(call)
        }
    },
}
