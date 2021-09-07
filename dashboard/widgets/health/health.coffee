### 
Author: suwonchon(schon@ebay.com)
###

class Dashing.Health extends Dashing.Widget

  ready: ->
    #console.log '[INFO] Get Data ready from health'

    if not @get('status')
      @set 'error', 'NO DATA'
      @set 'status', 'error'

  onData: (data) ->
    #console.log '[INFO] Get Data onData from health'

    status = switch
      when not (data.hasOwnProperty('warnings') and data.hasOwnProperty('criticals')) then 'error'
      when data.hasOwnProperty('error') then 'error'
      when @get('criticals') > 0 then 'red'
      when @get('warnings') > 0 then 'yellow'
      else 'green'

    @set 'status', status

    if status is 'error'
      if not data.hasOwnProperty('error')
        @set 'error', 'Data provided without "warnings" and "criticals" fields.'
